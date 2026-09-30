//! The emergency-mode gate: the reference pipeline's second check.
//!
//! This is the Rust family's port of
//! `guard_core/core/checks/implementations/emergency_mode.py`. One call,
//! [`decide`], decides a request IP against the emergency whitelist while
//! `config.emergency_mode` is active:
//!
//! ```text
//! whitelisted IP:   pass (the reference logs an INFO line only)
//! everyone else:    Denied (the reference's 503
//!                   "Service temporarily unavailable")
//! missing/unparseable IP: Denied (the reference's ValueError arm counts it
//!                         as non-whitelisted)
//! ```
//!
//! The switch itself stays on the stage wiring: the reference check is a
//! no-op unless `config.emergency_mode` is on (it is still constructed when
//! `enable_dynamic_rules` is on, watching for the switch), so the stage
//! holds the live switch and the engine holds the whitelist verdict.
//!
//! Entries match like every IP list in the family (a bare IP or a CIDR
//! range, IPv4-mapped canonicalization, families never crossing), the
//! reference `_ip_in_list`; [`EmergencyModeConfig::new`] fails closed on an
//! invalid entry.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::emergency_mode::{decide, EmergencyModeConfig, EmergencyVerdict};
//!
//! let config = EmergencyModeConfig::new(["192.0.2.40", "198.51.100.0/24"]).expect("valid");
//! assert_eq!(decide(Some("192.0.2.40"), &config), EmergencyVerdict::Allowed);
//! assert_eq!(decide(Some("192.0.2.41"), &config), EmergencyVerdict::Denied);
//! assert_eq!(decide(Some("198.51.100.7"), &config), EmergencyVerdict::Allowed);
//! // No client IP at all counts as non-whitelisted.
//! assert_eq!(decide(None, &config), EmergencyVerdict::Denied);
//! ```

use std::net::IpAddr;

use crate::ip_gate::{IpGateError, IpNet, canonical, parse_network_entry};

/// The check's stable name (`check_name`).
pub const EMERGENCY_MODE_CHECK_NAME: &str = "emergency_mode";

/// The block status the reference answers (`create_error_response(503,
/// default_message="Service temporarily unavailable")`).
pub const EMERGENCY_BLOCK_STATUS: u16 = 503;

/// The block body the reference answers with.
pub const EMERGENCY_BLOCK_BODY: &str = "Service temporarily unavailable";

/// The emergency whitelist (`SecurityConfig.emergency_whitelist`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmergencyModeConfig {
    whitelist: Vec<IpNet>,
}

impl EmergencyModeConfig {
    /// Parse the whitelist, failing closed on an invalid entry.
    ///
    /// # Errors
    ///
    /// [`IpGateError`] naming the first entry that is neither a valid IP
    /// nor a valid CIDR range.
    pub fn new<I>(entries: I) -> Result<Self, IpGateError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut whitelist = Vec::new();
        for entry in entries {
            let entry = entry.as_ref();
            match parse_network_entry(entry) {
                Some(network) => whitelist.push(network),
                None => {
                    return Err(IpGateError {
                        list: "emergency_whitelist",
                        entry: entry.to_owned(),
                    });
                }
            }
        }
        Ok(Self { whitelist })
    }

    /// How many entries the whitelist holds (the reference event's
    /// `emergency_whitelist_count` metadata).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.whitelist.len()
    }

    /// Whether the whitelist is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.whitelist.is_empty()
    }
}

/// What [`decide`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyVerdict {
    /// A whitelisted client: the reference logs INFO and lets it pass.
    Allowed,
    /// Everyone else while the mode is active: the reference's 503 shape.
    Denied,
}

/// The reference check body: a missing or unparseable IP is never
/// whitelisted (`ip_address(None)` / `ValueError` -> `client_ip_addr =
/// None`), a whitelisted one passes, everyone else is denied.
#[must_use]
pub fn decide(client_ip: Option<&str>, config: &EmergencyModeConfig) -> EmergencyVerdict {
    if let Some(raw) = client_ip
        && let Ok(addr) = raw.parse::<IpAddr>()
        && config
            .whitelist
            .iter()
            .any(|network| network.contains(canonical(addr)) || network.contains(addr))
    {
        return EmergencyVerdict::Allowed;
    }
    EmergencyVerdict::Denied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_members_pass_everyone_else_is_denied() {
        let config = EmergencyModeConfig::new(["192.0.2.40"]).unwrap();
        assert_eq!(
            decide(Some("192.0.2.40"), &config),
            EmergencyVerdict::Allowed
        );
        assert_eq!(
            decide(Some("192.0.2.41"), &config),
            EmergencyVerdict::Denied
        );
    }

    #[test]
    fn missing_or_unparseable_ip_is_denied() {
        let config = EmergencyModeConfig::new(["192.0.2.40"]).unwrap();
        assert_eq!(decide(None, &config), EmergencyVerdict::Denied);
        assert_eq!(decide(Some("not-an-ip"), &config), EmergencyVerdict::Denied);
        assert_eq!(decide(Some(""), &config), EmergencyVerdict::Denied);
    }

    #[test]
    fn cidr_entries_and_families_match_like_the_global_lists() {
        let config = EmergencyModeConfig::new(["198.51.100.0/24", "2001:db8:ffff::/48"]).unwrap();
        assert_eq!(
            decide(Some("198.51.100.7"), &config),
            EmergencyVerdict::Allowed
        );
        assert_eq!(
            decide(Some("::ffff:198.51.100.7"), &config),
            EmergencyVerdict::Allowed,
            "a v4-mapped request matches its IPv4 entry"
        );
        assert_eq!(
            decide(Some("2001:db8:ffff::9"), &config),
            EmergencyVerdict::Allowed
        );
        assert_eq!(
            decide(Some("198.51.101.7"), &config),
            EmergencyVerdict::Denied,
            "families and ranges never stretch"
        );
    }

    #[test]
    fn an_empty_whitelist_denies_everything() {
        let config = EmergencyModeConfig::new(Vec::<String>::new()).unwrap();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
        assert_eq!(
            decide(Some("192.0.2.40"), &config),
            EmergencyVerdict::Denied
        );
    }

    #[test]
    fn config_fails_closed_on_a_bad_entry() {
        let error = EmergencyModeConfig::new(["junk"]).unwrap_err();
        assert_eq!(error.list, "emergency_whitelist");
        assert_eq!(error.entry, "junk");
    }
}
