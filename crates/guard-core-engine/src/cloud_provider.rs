//! The cloud-provider IP table and block selectors.
//!
//! This is the Rust family's port of the reference engine's cloud-provider
//! blocking data path (`guard_core/handlers/cloud_handler.py` plus the
//! selector registry in `guard_core/handlers/_cloud_provider_registry.py`
//! and the config validation in `guard_core/models.py`). It carries three
//! pieces:
//!
//! - [`parse_cloud_selectors`]: the `block_cloud_providers` syntax. A bare
//!   name (`"GCP"`) blocks the whole provider; a `":!region"` suffix
//!   (`"GCP:!us-central1"`) blocks the provider **except** that region. An
//!   unrecognized provider name is a config error, exactly the reference
//!   `_validate_block_cloud_providers_value` `ValueError`.
//! - [`CloudIpTable`]: the provider ranges the block check consults. The
//!   reference keeps a module-singleton handler fed by background fetchers
//!   (with Redis caching and a refresh interval); those are I/O concerns
//!   this engine does not own, so the table is an in-memory store the
//!   adapter feeds (`set_provider_ranges`), shareable across clones.
//! - [`CloudIpTable::is_cloud_ip`]: the reference `is_cloud_ip` walk - for
//!   every selected provider that has ranges loaded, an address inside one
//!   of its networks is blocked unless the network's region is carved out.
//!
//! ## Details that mirror the reference exactly
//!
//! - Region carve-outs only exempt networks whose region is **known** (the
//!   reference `network_regions.get(str(network)) in allowed_regions`):
//!   a provider that publishes no region data (`Azure`, `DigitalOcean`,
//!   `Linode`, `Vultr`) blocks its whole provider even under a carve-out.
//! - Providers with no ranges loaded are skipped, not blocked (the
//!   reference `if provider not in self.ip_ranges: continue`), and an
//!   empty range set for a loaded provider blocks nothing (the reference
//!   only logs a warning).
//! - Family-strict matching: an IPv4 network never contains an IPv6
//!   address and vice versa, like `ipaddress` membership.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::cloud_provider::{parse_cloud_selectors, CloudIpTable};
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! // Block GCP except one region, and all of AWS.
//! let selectors = parse_cloud_selectors(["GCP:!us-central1", "AWS"]).expect("valid selectors");
//! let table = CloudIpTable::default();
//! table
//!     .set_provider_ranges(
//!         "AWS",
//!         vec![("203.0.113.0/24".to_owned(), None)],
//!     )
//!     .expect("valid ranges");
//! table
//!     .set_provider_ranges(
//!         "GCP",
//!         vec![
//!             ("198.51.100.0/24".to_owned(), Some("us-central1".to_owned())),
//!             ("198.51.101.0/24".to_owned(), Some("europe-west1".to_owned())),
//!         ],
//!     )
//!     .expect("valid ranges");
//!
//! // An AWS address is blocked ...
//! assert!(table.is_cloud_ip(IpAddr::from_str("203.0.113.9").unwrap(), &selectors));
//! // ... a GCP address in the carved-out region is not ...
//! assert!(!table.is_cloud_ip(IpAddr::from_str("198.51.100.9").unwrap(), &selectors));
//! // ... a GCP address elsewhere is ...
//! assert!(table.is_cloud_ip(IpAddr::from_str("198.51.101.9").unwrap(), &selectors));
//! // ... and a datacenter address belonging to nobody passes.
//! assert!(!table.is_cloud_ip(IpAddr::from_str("192.0.2.1").unwrap(), &selectors));
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

/// The providers the reference publishes range data for
/// (`VALID_CLOUD_PROVIDERS` / `_ALL_PROVIDERS`).
pub const VALID_CLOUD_PROVIDERS: [&str; 6] =
    ["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"];

/// The selector separator carving a region exception out of a block
/// (`":!"` in the reference `_parse_cloud_selectors`).
pub const CARVE_OUT_SEPARATOR: &str = ":!";

/// An invalid `block_cloud_providers` entry: the config error
/// [`parse_cloud_selectors`] fails closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudConfigError {
    /// The rejected selector.
    pub selector: String,
    /// The provider name the selector named (its text before the carve-out
    /// separator).
    pub provider: String,
}

impl fmt::Display for CloudConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut valid: Vec<&str> = VALID_CLOUD_PROVIDERS.to_vec();
        valid.sort_unstable();
        write!(
            f,
            "Unknown cloud providers in block_cloud_providers: [{}]. \
             Valid: [{}] (a bare name blocks the whole provider; \
             suffix ':!region' to carve out a region exception)",
            self.selector,
            valid.join(", ")
        )
    }
}

impl std::error::Error for CloudConfigError {}

/// The parsed `block_cloud_providers` selectors: the blocked provider
/// names in first-seen order, each optionally carrying carved-out regions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudSelectors {
    /// The blocked provider names (bare, without the carve-out suffix).
    pub blocked: Vec<String>,
    /// Provider -> the regions its block does NOT apply to.
    pub carveouts: HashMap<String, Vec<String>>,
}

/// Parse the `block_cloud_providers` selectors, failing closed on an
/// unknown provider name.
///
/// The selector provider must be one of [`VALID_CLOUD_PROVIDERS`], the
/// reference `_validate_block_cloud_providers_value` `ValueError`.
///
/// # Errors
///
/// [`CloudConfigError`] naming the first selector with an unknown provider.
pub fn parse_cloud_selectors<I, S>(selectors: I) -> Result<CloudSelectors, CloudConfigError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = CloudSelectors::default();
    for selector in selectors {
        let selector = selector.as_ref();
        let (provider, marker, region) = partition_carve_out(selector);
        if !VALID_CLOUD_PROVIDERS.contains(&provider) {
            return Err(CloudConfigError {
                selector: selector.to_owned(),
                provider: provider.to_owned(),
            });
        }
        if !parsed.blocked.iter().any(|name| name == provider) {
            parsed.blocked.push(provider.to_owned());
        }
        if marker && !region.is_empty() {
            let regions = parsed.carveouts.entry(provider.to_owned()).or_default();
            if !regions.iter().any(|known| known == region) {
                regions.push(region.to_owned());
            }
        }
    }
    Ok(parsed)
}

/// Split one selector into `(provider, had_marker, region)` - the reference
/// `selector.partition(":!")`.
fn partition_carve_out(selector: &str) -> (&str, bool, &str) {
    match selector.split_once(CARVE_OUT_SEPARATOR) {
        Some((provider, region)) => (provider, true, region),
        None => (selector, false, ""),
    }
}

/// One parsed network entry: a CIDR range (or a bare address) with the host
/// bits cleared, family-strict membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    /// Parse an `addr/prefix` entry (or a bare address), clearing the host
    /// bits - `ip_network(entry, strict=False)` in the reference.
    fn parse(text: &str) -> Option<Self> {
        if let Some((addr_part, prefix_part)) = text.split_once('/') {
            let addr = IpAddr::from_str(addr_part).ok()?;
            let prefix = u8::from_str(prefix_part).ok()?;
            if prefix > family_bits(addr) {
                return None;
            }
            return Some(Self {
                addr: masked(addr, prefix),
                prefix,
            });
        }
        let addr = IpAddr::from_str(text).ok()?;
        Some(Self {
            addr,
            prefix: family_bits(addr),
        })
    }

    /// Family-strict membership: a v4 network never contains a v6 address.
    fn contains(&self, addr: IpAddr) -> bool {
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

impl fmt::Display for Network {
    /// The canonical `addr/prefix` form (`str(ip_network(...))` in the
    /// reference, host bits cleared).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
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

const fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// One provider's loaded ranges plus the region each network belongs to
/// (absent for providers that publish no region data).
#[derive(Debug, Clone, Default)]
struct ProviderRanges {
    networks: Vec<Network>,
    regions: HashMap<String, String>,
}

/// The provider ranges the block check consults.
///
/// The default table is empty: every provider is unloaded and
/// [`CloudIpTable::is_cloud_ip`] blocks nothing until the adapter feeds
/// ranges. Clones share the store (the reference module-singleton
/// semantics), so a background refresher can swap ranges under an
/// installed stage.
#[derive(Clone, Default)]
pub struct CloudIpTable {
    inner: Arc<RwLock<HashMap<String, ProviderRanges>>>,
}

impl fmt::Debug for CloudIpTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudIpTable").finish_non_exhaustive()
    }
}

impl CloudIpTable {
    /// Load (or replace) one provider's ranges: `(cidr, region)` pairs,
    /// the region absent for providers that publish none.
    ///
    /// # Errors
    ///
    /// Returns `(cidr, error)` for the first entry that is neither a CIDR
    /// range nor a bare address - the reference fetchers only produce
    /// valid networks, so this port fails loudly instead of silently
    /// dropping an entry.
    pub fn set_provider_ranges(
        &self,
        provider: &str,
        entries: Vec<(String, Option<String>)>,
    ) -> Result<(), (String, CloudRangeError)> {
        let mut networks = Vec::with_capacity(entries.len());
        let mut regions = HashMap::new();
        for (cidr, region) in entries {
            let network =
                Network::parse(&cidr).ok_or_else(|| (cidr.clone(), CloudRangeError { cidr }))?;
            if let Some(region) = region {
                regions.insert(network.to_string(), region);
            }
            networks.push(network);
        }
        self.inner
            .write()
            .expect("cloud provider table")
            .insert(provider.to_owned(), ProviderRanges { networks, regions });
        Ok(())
    }

    /// Drop one provider's ranges (the reference's failed-refresh shape:
    /// an unloaded provider is skipped, not blocked).
    pub fn clear_provider(&self, provider: &str) {
        self.inner
            .write()
            .expect("cloud provider table")
            .remove(provider);
    }

    /// Whether a provider has any ranges loaded (the reference
    /// `get_status`'s `ready` flag).
    #[must_use]
    pub fn provider_is_ready(&self, provider: &str) -> bool {
        self.inner
            .read()
            .expect("cloud provider table")
            .get(provider)
            .is_some_and(|ranges| !ranges.networks.is_empty())
    }

    /// The reference `is_cloud_ip`: whether `ip` falls inside a blocked
    /// provider's network, honoring the region carve-outs.
    // The read guard must outlive the whole network walk (every iteration
    // reads through the `ranges` reference it produced); the nursery lint
    // cannot see that and wants it dropped per provider. One acquisition
    // for the whole walk is the point.
    #[allow(clippy::significant_drop_tightening)]
    #[must_use]
    pub fn is_cloud_ip(&self, ip: IpAddr, selectors: &CloudSelectors) -> bool {
        let table = self.inner.read().expect("cloud provider table");
        selectors.blocked.iter().any(|provider| {
            let Some(ranges) = table.get(provider) else {
                return false;
            };
            let allowed_regions = selectors.carveouts.get(provider);
            ranges.networks.iter().any(|network| {
                if !network.contains(ip) {
                    return false;
                }
                let carved_out = allowed_regions.is_some_and(|allowed| {
                    ranges
                        .regions
                        .get(&network.to_string())
                        .is_some_and(|region| allowed.iter().any(|name| name == region))
                });
                !carved_out
            })
        })
    }

    /// The reference `get_cloud_provider_details`: the first
    /// `(provider, network)` pair (in selector order) whose ranges contain
    /// `ip`.
    #[must_use]
    pub fn provider_details(
        &self,
        ip: IpAddr,
        selectors: &CloudSelectors,
    ) -> Option<(String, String)> {
        let table = self.inner.read().expect("cloud provider table");
        for provider in &selectors.blocked {
            if let Some(ranges) = table.get(provider) {
                for network in &ranges.networks {
                    if network.contains(ip) {
                        return Some((provider.clone(), network.to_string()));
                    }
                }
            }
        }
        None
    }
}

/// An invalid range entry: the error [`CloudIpTable::set_provider_ranges`]
/// fails with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudRangeError {
    /// The rejected entry.
    pub cidr: String,
}

impl fmt::Display for CloudRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid cloud provider range '{}': expected an IP address or CIDR range",
            self.cidr
        )
    }
}

impl std::error::Error for CloudRangeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    #[test]
    fn selectors_parse_bare_and_carve_out_forms() {
        let selectors = parse_cloud_selectors(["GCP:!us-central1", "AWS", "GCP:!europe-west1"])
            .expect("valid selectors");
        assert_eq!(selectors.blocked, vec!["GCP".to_owned(), "AWS".to_owned()]);
        assert_eq!(
            selectors.carveouts.get("GCP").expect("carveouts"),
            &vec!["us-central1".to_owned(), "europe-west1".to_owned()]
        );
        assert!(!selectors.carveouts.contains_key("AWS"));

        let selectors = parse_cloud_selectors(["Linode"]).expect("valid selectors");
        assert_eq!(selectors.blocked, vec!["Linode".to_owned()]);
        assert!(selectors.carveouts.is_empty());
    }

    #[test]
    fn unknown_provider_fails_closed_with_the_reference_message() {
        let error = parse_cloud_selectors(["GCP", "Hetzner"]).unwrap_err();
        assert_eq!(error.selector, "Hetzner");
        assert_eq!(error.provider, "Hetzner");
        assert_eq!(
            error.to_string(),
            "Unknown cloud providers in block_cloud_providers: [Hetzner]. \
             Valid: [AWS, Azure, DigitalOcean, GCP, Linode, Vultr] \
             (a bare name blocks the whole provider; \
             suffix ':!region' to carve out a region exception)"
        );
        // Provider names are exact: no case folding, like the reference set.
        assert!(parse_cloud_selectors(["aws"]).is_err());
        // An empty carve-out region is a bare block, not an error.
        let selectors = parse_cloud_selectors(["GCP:!"]).expect("valid selectors");
        assert_eq!(selectors.blocked, vec!["GCP".to_owned()]);
        assert!(!selectors.carveouts.contains_key("GCP"));
    }

    #[test]
    fn network_parse_clears_host_bits_and_display_is_canonical() {
        let network = Network::parse("203.0.113.77/24").expect("parses");
        assert_eq!(network.to_string(), "203.0.113.0/24");
        // A bare address is a single-host network.
        let network = Network::parse("203.0.113.7").expect("parses");
        assert_eq!(network.to_string(), "203.0.113.7/32");
        let network = Network::parse("2001:db8::5").expect("parses");
        assert_eq!(network.to_string(), "2001:db8::5/128");
    }

    #[test]
    fn network_parse_rejects_junk() {
        for junk in ["not-an-ip", "203.0.113.0/33", "203.0.113.7/", "/24", ""] {
            assert!(Network::parse(junk).is_none(), "{junk} must not parse");
        }
    }

    #[test]
    fn membership_is_family_strict() {
        let network = Network::parse("203.0.113.0/24").expect("v4");
        assert!(network.contains(ip("203.0.113.9")));
        assert!(!network.contains(ip("2001:db8::1")));
        let network = Network::parse("2001:db8::/32").expect("v6");
        assert!(network.contains(ip("2001:db8::9")));
        assert!(!network.contains(ip("203.0.113.9")));
    }

    #[test]
    fn an_empty_table_blocks_nothing() {
        let selectors = parse_cloud_selectors(VALID_CLOUD_PROVIDERS).expect("valid selectors");
        let table = CloudIpTable::default();
        assert!(!table.is_cloud_ip(ip("203.0.113.9"), &selectors));
        assert!(!table.provider_is_ready("AWS"));
    }

    #[test]
    fn loaded_provider_blocks_its_ranges() {
        let selectors = parse_cloud_selectors(["AWS"]).expect("valid selectors");
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        assert!(table.provider_is_ready("AWS"));
        assert!(table.is_cloud_ip(ip("203.0.113.9"), &selectors));
        assert!(!table.is_cloud_ip(ip("203.0.114.9"), &selectors));
        assert!(!table.is_cloud_ip(ip("2001:db8::9"), &selectors));
    }

    #[test]
    fn an_unloaded_selected_provider_is_skipped_not_blocking() {
        let selectors = parse_cloud_selectors(["GCP", "AWS"]).expect("valid selectors");
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        // The unloaded GCP ranges block nothing; the address outside AWS
        // passes.
        assert!(!table.is_cloud_ip(ip("192.0.2.9"), &selectors));
        assert!(table.is_cloud_ip(ip("203.0.113.9"), &selectors));
    }

    #[test]
    fn a_cleared_provider_stops_blocking() {
        let selectors = parse_cloud_selectors(["AWS"]).expect("valid selectors");
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        assert!(table.is_cloud_ip(ip("203.0.113.9"), &selectors));
        table.clear_provider("AWS");
        assert!(!table.is_cloud_ip(ip("203.0.113.9"), &selectors));
        assert!(!table.provider_is_ready("AWS"));
    }

    #[test]
    fn carve_outs_exempt_only_networks_with_a_known_region() {
        let selectors = parse_cloud_selectors(["GCP:!us-central1"]).expect("valid selectors");
        let table = CloudIpTable::default();
        table
            .set_provider_ranges(
                "GCP",
                vec![
                    ("198.51.100.0/24".to_owned(), Some("us-central1".to_owned())),
                    (
                        "198.51.101.0/24".to_owned(),
                        Some("europe-west1".to_owned()),
                    ),
                ],
            )
            .expect("valid ranges");
        assert!(!table.is_cloud_ip(ip("198.51.100.9"), &selectors));
        assert!(table.is_cloud_ip(ip("198.51.101.9"), &selectors));

        // A provider without region data blocks everything under a
        // carve-out: an unknown region can never match.
        let selectors = parse_cloud_selectors(["Azure:!somewhere"]).expect("valid selectors");
        table
            .set_provider_ranges("Azure", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        assert!(table.is_cloud_ip(ip("203.0.113.9"), &selectors));
    }

    #[test]
    fn set_provider_ranges_fails_closed_on_a_junk_entry() {
        let table = CloudIpTable::default();
        let error = table
            .set_provider_ranges("AWS", vec![("not-a-range".to_owned(), None)])
            .unwrap_err();
        assert_eq!(error.0, "not-a-range");
        assert_eq!(
            error.1.to_string(),
            "invalid cloud provider range 'not-a-range': expected an IP address or CIDR range"
        );
        // The provider stays unloaded after the failure.
        let selectors = parse_cloud_selectors(["AWS"]).expect("valid selectors");
        assert!(!table.is_cloud_ip(ip("203.0.113.9"), &selectors));
    }

    #[test]
    fn details_report_the_first_matching_selector_provider() {
        let selectors = parse_cloud_selectors(["GCP", "AWS"]).expect("valid selectors");
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("GCP", vec![("198.51.100.0/24".to_owned(), None)])
            .expect("valid ranges");
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        assert_eq!(
            table.provider_details(ip("203.0.113.9"), &selectors),
            Some(("AWS".to_owned(), "203.0.113.0/24".to_owned()))
        );
        assert_eq!(
            table.provider_details(ip("198.51.100.9"), &selectors),
            Some(("GCP".to_owned(), "198.51.100.0/24".to_owned()))
        );
        assert_eq!(table.provider_details(ip("192.0.2.9"), &selectors), None);
    }

    #[test]
    fn clones_share_the_table() {
        let selectors = parse_cloud_selectors(["AWS"]).expect("valid selectors");
        let table = CloudIpTable::default();
        let clone = table.clone();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        assert!(clone.is_cloud_ip(ip("203.0.113.9"), &selectors));
    }

    #[test]
    fn masks_handle_the_zero_prefixes_and_render_debug() {
        assert_eq!(masked(ip("192.0.2.9"), 0), ip("0.0.0.0"));
        assert_eq!(masked(ip("192.0.2.9"), 32), ip("192.0.2.9"));
        assert_eq!(
            masked(IpAddr::V6("2001:db8::1".parse().expect("v6")), 0),
            ip("::")
        );
        let table = CloudIpTable::default();
        assert!(format!("{table:?}").contains("CloudIpTable"));
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn a_provider_without_fed_ranges_has_no_details_and_blocks_nothing() {
        // the selectors parse (AWS is a known provider) but the table was
        // never fed its ranges
        let table = CloudIpTable::default();
        let selectors = parse_cloud_selectors(["AWS"]).expect("valid selectors");
        let probe = "203.0.113.9".parse().expect("ip");
        assert!(table.provider_details(probe, &selectors).is_none());
        assert!(!table.is_cloud_ip(probe, &selectors));
    }
}
