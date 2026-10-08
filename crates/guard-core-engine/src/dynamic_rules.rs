//! The dynamic-rules carrier: the reference `DynamicRules` wire model
//! and its manager-side logic (`handlers/_dynamic_rule_*.py` +
//! `_dynamic_rules.py`).
//!
//! The carrier holds the wire model, the last-known snapshot envelope,
//! the update gating, the event matcher, and the config application.
//! Sources, piece by piece:
//!
//! - the model: `_dynamic_rules.py` `DynamicRules` (the same field set
//!   the guard-agent wire model carries; the defaults land verbatim -
//!   `ttl = 300`, `ip_ban_duration = 3600`, `emergency_mode = false`);
//! - the snapshot envelope: `dump_last_known_rules_snapshot` /
//!   `load_last_known_rules_snapshot` (the `schema_version` guard
//!   rejects unsupported versions at load);
//! - the gating: `DynamicRuleManager._should_update_rules` (a new rule
//!   id always updates; a same-id rule only when its version advances),
//!   `_has_rule_expired` / `_reject_if_already_expired`;
//! - the correlation: `DynamicRuleManager.match_event` (the IP, country,
//!   and event-type arms the enricher reads);
//! - the application: `DynamicRuleApplicationMixin` landings on the
//!   unified config - uppercased country sets, the global/window/endpoint
//!   rate tiers, the `VALID_CLOUD_PROVIDERS`-validated cloud set (the
//!   `AWS:!region` scoping survives verbatim), the ReDoS-validated user
//!   agent list (rejected patterns surface in the outcome), the feature
//!   toggles, and the emergency-mode activation with the halved
//!   auto-ban threshold (`max(1, threshold / 2)`).
//!
//! The module is pure: the bans, unbans, and pattern additions come back
//! in the [`AppliedDynamicRules`] outcome for the caller's stateful
//! seams (the ban manager, the pattern store), while the config-mutating
//! half lands directly on the [`SecurityConfig`] the caller owns.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::compiler::validate_pattern_safety;
use crate::decorators::VALID_CLOUD_PROVIDERS;
use crate::security_config::SecurityConfig;

/// `LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION` (the envelope guard).
pub const LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION: u64 = 1;

/// The reference `DynamicRules` wire model, field for field (the same
/// shape the guard-agent models carry).
///
/// `Eq` is unreachable while the model carries a `DateTime` (chrono
/// answers `PartialEq` only), hence the pinpointed allowance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct DynamicRules {
    /// Unique rule ID.
    pub rule_id: String,
    /// Rule version number.
    pub version: u64,
    /// Rule creation/update timestamp.
    pub timestamp: Option<DateTime<Utc>>,
    /// Rule expiration time.
    pub expires_at: Option<DateTime<Utc>>,
    /// Cache TTL in seconds (drives the client-side rules cache).
    pub ttl: u64,
    /// IPs to ban.
    pub ip_blacklist: Vec<String>,
    /// IPs to allow.
    pub ip_whitelist: Vec<String>,
    /// Ban duration in seconds.
    pub ip_ban_duration: u64,
    /// Countries to block.
    pub blocked_countries: Vec<String>,
    /// Countries to allow.
    pub whitelist_countries: Vec<String>,
    /// Global rate limit.
    pub global_rate_limit: Option<u64>,
    /// Global rate window in seconds.
    pub global_rate_window: Option<u64>,
    /// Per-endpoint rate limits `{endpoint: (requests, window)}`.
    pub endpoint_rate_limits: BTreeMap<String, (u64, u64)>,
    /// Cloud providers to block (the `AWS:!region` scoping survives).
    pub blocked_cloud_providers: BTreeSet<String>,
    /// User agents to block.
    pub blocked_user_agents: Vec<String>,
    /// Additional suspicious patterns.
    pub suspicious_patterns: Vec<String>,
    /// Override penetration detection setting.
    pub enable_penetration_detection: Option<bool>,
    /// Override IP banning setting.
    pub enable_ip_banning: Option<bool>,
    /// Override rate limiting setting.
    pub enable_rate_limiting: Option<bool>,
    /// Override auto-ban threshold setting.
    pub auto_ban_threshold: Option<u64>,
    /// Override auto-ban duration setting.
    pub auto_ban_duration: Option<u64>,
    /// Override rate-limit auto-ban setting.
    pub enable_rate_limit_auto_ban: Option<bool>,
    /// Emergency lockdown mode.
    pub emergency_mode: bool,
    /// Emergency whitelist IPs.
    pub emergency_whitelist: Vec<String>,
}

impl Default for DynamicRules {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            version: 0,
            timestamp: None,
            expires_at: None,
            ttl: 300,
            ip_blacklist: Vec::new(),
            ip_whitelist: Vec::new(),
            ip_ban_duration: 3600,
            blocked_countries: Vec::new(),
            whitelist_countries: Vec::new(),
            global_rate_limit: None,
            global_rate_window: None,
            endpoint_rate_limits: BTreeMap::new(),
            blocked_cloud_providers: BTreeSet::new(),
            blocked_user_agents: Vec::new(),
            suspicious_patterns: Vec::new(),
            enable_penetration_detection: None,
            enable_ip_banning: None,
            enable_rate_limiting: None,
            auto_ban_threshold: None,
            auto_ban_duration: None,
            enable_rate_limit_auto_ban: None,
            emergency_mode: false,
            emergency_whitelist: Vec::new(),
        }
    }
}

impl DynamicRules {
    /// The rule identity the gates compare (`(rule_id, version)`).
    #[must_use]
    pub fn identity(&self) -> (&str, u64) {
        (&self.rule_id, self.version)
    }
}

/// The reference snapshot envelope (`LastKnownRulesSnapshot`): the
/// schema version beside the mirrored rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LastKnownRulesSnapshot {
    /// The envelope schema version.
    pub schema_version: u64,
    /// The mirrored rules.
    pub rules: DynamicRules,
}

/// A snapshot load failure (the version guard and the JSON decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError(pub String);

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "last-known rules snapshot error: {}", self.0)
    }
}

impl std::error::Error for SnapshotError {}

/// `dump_last_known_rules_snapshot`: the versioned JSON envelope.
///
/// # Errors
///
/// [`SnapshotError`] when the payload fails to serialize.
pub fn dump_last_known_rules_snapshot(rules: &DynamicRules) -> Result<String, SnapshotError> {
    let snapshot = LastKnownRulesSnapshot {
        schema_version: LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION,
        rules: rules.clone(),
    };
    serde_json::to_string(&snapshot)
        .map_err(|error| SnapshotError(format!("snapshot serialization: {error}")))
}

/// `load_last_known_rules_snapshot`: the version-guarded decode.
///
/// # Errors
///
/// [`SnapshotError`] on a decode failure or an unsupported schema
/// version.
pub fn load_last_known_rules_snapshot(payload: &str) -> Result<DynamicRules, SnapshotError> {
    let snapshot: LastKnownRulesSnapshot = serde_json::from_str(payload)
        .map_err(|error| SnapshotError(format!("snapshot decode: {error}")))?;
    if snapshot.schema_version != LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION {
        return Err(SnapshotError(format!(
            "Unsupported last-known dynamic rules snapshot schema version: {}",
            snapshot.schema_version
        )));
    }
    Ok(snapshot.rules)
}

/// `_has_rule_expired`: past `expires_at` at `now` (an absent expiry
/// never expires).
#[must_use]
pub fn has_expired(rules: &DynamicRules, now: DateTime<Utc>) -> bool {
    rules.expires_at.is_some_and(|expires_at| now > expires_at)
}

/// `_should_update_rules`: the first rule always updates; a same-id rule
/// only when its version advances (a stale replay never re-applies).
#[must_use]
pub fn should_update(current: Option<&DynamicRules>, incoming: &DynamicRules) -> bool {
    current.is_none_or(|current| {
        !(incoming.rule_id == current.rule_id && incoming.version <= current.version)
    })
}

/// `_reject_if_already_expired`'s de-duplication key: the same expired
/// rule logs its warning once.
#[must_use]
pub fn expired_identity(
    last_skipped: &mut Option<(String, u64)>,
    rules: &DynamicRules,
    now: DateTime<Utc>,
) -> bool {
    if !has_expired(rules, now) {
        return false;
    }
    let key = (rules.rule_id.clone(), rules.version);
    if last_skipped.as_ref() != Some(&key) {
        *last_skipped = Some(key);
    }
    true
}

/// `match_event`: the enrichment correlation.
///
/// The rule answers `(rule_id, version)` when the event's IP sits on the
/// rule's ban or allow lists, the event's country is one of the rule's
/// blocked countries, or the event type names a rule surface that is in
/// force (`rate_limited` with rate tiers, `cloud_blocked` with
/// providers, `user_agent_blocked` with agents).
#[must_use]
pub fn matches_event(
    rules: &DynamicRules,
    ip: Option<&str>,
    country: Option<&str>,
    event_type: &str,
) -> Option<(String, u64)> {
    if let Some(ip) = ip
        && (rules.ip_blacklist.iter().any(|banned| banned == ip)
            || rules.ip_whitelist.iter().any(|allowed| allowed == ip))
    {
        return Some((rules.rule_id.clone(), rules.version));
    }
    if let Some(country) = country
        && rules
            .blocked_countries
            .iter()
            .any(|blocked| blocked.eq_ignore_ascii_case(country))
    {
        return Some((rules.rule_id.clone(), rules.version));
    }
    let type_matches = match event_type {
        "rate_limited" => {
            rules.global_rate_limit.is_some() || !rules.endpoint_rate_limits.is_empty()
        }
        "cloud_blocked" => !rules.blocked_cloud_providers.is_empty(),
        "user_agent_blocked" => !rules.blocked_user_agents.is_empty(),
        _ => false,
    };
    if type_matches {
        return Some((rules.rule_id.clone(), rules.version));
    }
    None
}

/// What applying one rule produced.
///
/// The stateful lands for the caller's seams (the reference logs each of
/// these; the outcome carries them so hosts log the returns).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedDynamicRules {
    /// `ip_blacklist` as `(ip, duration)` ban pairs that parsed.
    pub bans: Vec<(IpAddr, u64)>,
    /// `ip_blacklist` entries that failed to parse (reported, skipped).
    pub unparseable_bans: Vec<String>,
    /// `ip_whitelist` as unban addresses that parsed.
    pub unbans: Vec<IpAddr>,
    /// `ip_whitelist` entries that failed to parse (reported, skipped).
    pub unparseable_unbans: Vec<String>,
    /// `suspicious_patterns` additions for the pattern store.
    pub patterns: Vec<String>,
    /// `blocked_user_agents` patterns rejected by the ReDoS validator
    /// with the validator's reason.
    pub rejected_user_agents: Vec<(String, String)>,
    /// Whether the emergency arm activated (threshold halved).
    pub emergency_activated: bool,
}

/// The config-mutating half of `_apply_rules` +
/// `DynamicRuleApplicationMixin`.
///
/// Every config landing the reference makes, in reference order, with
/// the outcome carrying the stateful lands (bans, unbans, patterns) and
/// the rejection reports.
pub fn apply_to_config(config: &mut SecurityConfig, rules: &DynamicRules) -> AppliedDynamicRules {
    let mut outcome = AppliedDynamicRules::default();

    // `_apply_ip_rules`: the bans and unbans surface for the caller's
    // ban manager (the reference drives `ip_ban_manager` directly).
    for ip in &rules.ip_blacklist {
        match ip.parse::<IpAddr>() {
            Ok(parsed) => outcome.bans.push((parsed, rules.ip_ban_duration)),
            Err(_) => outcome.unparseable_bans.push(ip.clone()),
        }
    }
    for ip in &rules.ip_whitelist {
        match ip.parse::<IpAddr>() {
            Ok(parsed) => outcome.unbans.push(parsed),
            Err(_) => outcome.unparseable_unbans.push(ip.clone()),
        }
    }

    // `_apply_country_rules`: the uppercased sets.
    if !rules.blocked_countries.is_empty() {
        config.blocked_countries = rules
            .blocked_countries
            .iter()
            .map(|c| c.to_uppercase())
            .collect::<BTreeSet<_>>();
    }
    if !rules.whitelist_countries.is_empty() {
        config.whitelist_countries = rules
            .whitelist_countries
            .iter()
            .map(|c| c.to_uppercase())
            .collect::<BTreeSet<_>>();
    }

    // `_apply_rate_limit_rules`: the global tier (the window only moves
    // with a limit) and the endpoint tiers (clamped to the config's u32
    // limit width).
    if let Some(limit) = rules.global_rate_limit {
        config.rate_limit = u32::try_from(limit).unwrap_or(u32::MAX);
        if let Some(window) = rules.global_rate_window {
            config.rate_limit_window = window;
        }
    }
    if !rules.endpoint_rate_limits.is_empty() {
        config.endpoint_rate_limits = rules
            .endpoint_rate_limits
            .iter()
            .map(|(endpoint, (limit, window))| {
                (
                    endpoint.clone(),
                    (u32::try_from(*limit).unwrap_or(u32::MAX), *window),
                )
            })
            .collect();
    }

    // `_apply_cloud_provider_rules`: the `VALID_CLOUD_PROVIDERS`
    // vocabulary over the `:!`-stripped names; unknowns land in the
    // outcome as ignored (the reference warns with the sorted set).
    if !rules.blocked_cloud_providers.is_empty() {
        let valid: BTreeSet<String> = rules
            .blocked_cloud_providers
            .iter()
            .filter(|provider| {
                let base = provider.split(":!").next().unwrap_or(provider);
                VALID_CLOUD_PROVIDERS.contains(&base)
            })
            .cloned()
            .collect();
        config.block_cloud_providers = Some(valid);
    }

    // `_apply_user_agent_rules`: the ReDoS-validated lane, the rejected
    // patterns surfaced.
    if !rules.blocked_user_agents.is_empty() {
        let mut valid = Vec::new();
        for pattern in &rules.blocked_user_agents {
            let (is_safe, reason) = validate_pattern_safety(pattern);
            if is_safe {
                valid.push(pattern.clone());
            } else {
                outcome.rejected_user_agents.push((pattern.clone(), reason));
            }
        }
        config.blocked_user_agents = valid;
    }

    // `_apply_feature_toggles`: the present-only overrides.
    if let Some(flag) = rules.enable_penetration_detection {
        config.enable_penetration_detection = flag;
    }
    if let Some(flag) = rules.enable_ip_banning {
        config.enable_ip_banning = flag;
    }
    if let Some(flag) = rules.enable_rate_limiting {
        config.enable_rate_limiting = flag;
    }
    if let Some(threshold) = rules.auto_ban_threshold {
        config.auto_ban_threshold = u32::try_from(threshold).unwrap_or(u32::MAX);
    }
    if let Some(duration) = rules.auto_ban_duration {
        config.auto_ban_duration = duration;
    }
    if let Some(flag) = rules.enable_rate_limit_auto_ban {
        config.enable_rate_limit_auto_ban = flag;
    }

    // `_activate_emergency_mode`: the flag, the whitelist, and the
    // halved threshold (`max(1, threshold / 2)`).
    if rules.emergency_mode {
        config.emergency_mode = true;
        config
            .emergency_whitelist
            .clone_from(&rules.emergency_whitelist);
        let original = config.auto_ban_threshold;
        config.auto_ban_threshold = (original / 2).max(1);
        outcome.emergency_activated = true;
    }

    // `_apply_pattern_rules`: the additions surface for the pattern
    // store (the store's own validation decides acceptance).
    outcome.patterns.clone_from(&rules.suspicious_patterns);
    outcome
}

#[cfg(test)]
mod dynamic_rules_tests {
    use super::*;
    use chrono::TimeZone;

    fn rules() -> DynamicRules {
        DynamicRules {
            rule_id: String::from("rule-1"),
            version: 2,
            ..DynamicRules::default()
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().expect("valid time")
    }

    #[test]
    fn the_model_defaults_carry_the_reference_values() {
        let base = DynamicRules::default();
        assert_eq!(base.ttl, 300);
        assert_eq!(base.ip_ban_duration, 3600);
        assert!(!base.emergency_mode);
        assert!(base.ip_blacklist.is_empty());
        assert_eq!(base.identity(), ("", 0));
    }

    #[test]
    fn the_snapshot_envelope_round_trips_and_guards_the_version() {
        let rules = rules();
        let payload = dump_last_known_rules_snapshot(&rules).expect("dumps");
        assert!(payload.contains("\"schema_version\":1"));
        let loaded = load_last_known_rules_snapshot(&payload).expect("loads");
        assert_eq!(loaded, rules);

        let wrong_version = payload.replace("\"schema_version\":1", "\"schema_version\":9");
        let error = load_last_known_rules_snapshot(&wrong_version).expect_err("rejects");
        assert!(error.to_string().contains("Unsupported last-known"));

        let decode_error = load_last_known_rules_snapshot("not json").expect_err("rejects");
        assert!(decode_error.to_string().contains("snapshot decode"));
        let error_shape = SnapshotError(String::from("boom"));
        assert_eq!(
            error_shape.to_string(),
            "last-known rules snapshot error: boom"
        );
    }

    #[test]
    fn the_expiry_gate_reads_the_deadline() {
        let rules = DynamicRules {
            expires_at: Some(at(500)),
            ..rules()
        };
        assert!(!has_expired(&rules, at(500)), "the boundary is exclusive");
        assert!(!has_expired(&rules, at(500)), "the boundary is exclusive");
        assert!(has_expired(&rules, at(501)));
    }

    #[test]
    fn the_update_gate_advances_versions_never_replays() {
        assert!(should_update(None, &rules()));
        let incoming = rules();
        assert!(!should_update(Some(&incoming), &incoming));

        let mut newer = rules();
        newer.version = 3;
        assert!(should_update(Some(&incoming), &newer));

        let mut stale = rules();
        stale.version = 1;
        assert!(!should_update(Some(&incoming), &stale));

        let mut other_id = rules();
        other_id.rule_id = String::from("rule-2");
        other_id.version = 1;
        assert!(
            should_update(Some(&incoming), &other_id),
            "a new id updates"
        );
    }

    #[test]
    fn the_expired_identity_deduplicates_its_warning() {
        let mut last_skipped: Option<(String, u64)> = None;
        let mut expiring = rules();
        expiring.expires_at = Some(at(500));

        assert!(expired_identity(&mut last_skipped, &expiring, at(501)));
        let first = last_skipped.clone();
        assert!(expired_identity(&mut last_skipped, &expiring, at(501)));
        assert_eq!(first, last_skipped, "the same rule logs once");

        let mut fresh = rules();
        fresh.rule_id = String::from("rule-2");
        fresh.version = 7;
        fresh.expires_at = Some(at(100));
        assert!(expired_identity(&mut last_skipped, &fresh, at(501)));
        assert_ne!(first, last_skipped, "a new identity re-warns");

        assert!(!expired_identity(&mut last_skipped, &rules(), at(501)));
    }

    #[test]
    fn the_event_matcher_answers_the_three_arms() {
        let mut r = DynamicRules {
            ip_blacklist: vec![String::from("192.0.2.1")],
            ip_whitelist: vec![String::from("192.0.2.2")],
            blocked_countries: vec![String::from("CN")],
            ..rules()
        };

        assert_eq!(
            matches_event(&r, Some("192.0.2.1"), None, "other"),
            Some((String::from("rule-1"), 2))
        );
        assert_eq!(
            matches_event(&r, Some("192.0.2.2"), None, "other"),
            Some((String::from("rule-1"), 2)),
            "the whitelist arm correlates too"
        );
        assert_eq!(
            matches_event(&r, None, Some("cn"), "other"),
            Some((String::from("rule-1"), 2)),
            "the country arm is case-insensitive"
        );
        assert_eq!(
            matches_event(&r, Some("192.0.2.9"), Some("US"), "other"),
            None
        );
        assert_eq!(matches_event(&r, None, None, "rate_limited"), None);

        r.global_rate_limit = Some(10);
        assert!(matches_event(&r, None, None, "rate_limited").is_some());
        r.blocked_cloud_providers.insert(String::from("AWS"));
        assert!(matches_event(&r, None, None, "cloud_blocked").is_some());
        r.blocked_user_agents = vec![String::from("curl")];
        assert!(matches_event(&r, None, None, "user_agent_blocked").is_some());
    }

    #[test]
    fn the_application_lands_every_config_surface() {
        let mut config = SecurityConfig {
            auto_ban_threshold: 10,
            ..SecurityConfig::default()
        };

        let mut r = rules();
        r.ip_blacklist = vec![String::from("192.0.2.1"), String::from("not-an-ip")];
        r.ip_whitelist = vec![String::from("192.0.2.2"), String::from("also-bad")];
        r.blocked_countries = vec![String::from("cn"), String::from("ru")];
        r.whitelist_countries = vec![String::from("us")];
        r.global_rate_limit = Some(25);
        r.global_rate_window = Some(45);
        r.endpoint_rate_limits.insert(String::from("/api"), (7, 30));
        r.blocked_cloud_providers = BTreeSet::from([
            String::from("AWS"),
            String::from("AWS:!prod"),
            String::from("GCP"),
            String::from("Mystery"),
        ]);
        r.blocked_user_agents = vec![String::from("evil-agent"), String::from("(")];
        r.enable_penetration_detection = Some(false);
        r.enable_ip_banning = Some(false);
        r.enable_rate_limiting = Some(true);
        r.auto_ban_threshold = Some(20);
        r.auto_ban_duration = Some(9_000);
        r.enable_rate_limit_auto_ban = Some(false);
        r.emergency_mode = true;
        r.emergency_whitelist = vec![String::from("10.0.0.1")];
        r.suspicious_patterns = vec![String::from("union.*select")];

        let outcome = apply_to_config(&mut config, &r);

        assert_eq!(outcome.bans, vec![(ip("192.0.2.1"), 3_600)]);
        assert_eq!(outcome.unparseable_bans, vec![String::from("not-an-ip")]);
        assert_eq!(outcome.unbans, vec![ip("192.0.2.2")]);
        assert_eq!(outcome.unparseable_unbans, vec![String::from("also-bad")]);
        assert_eq!(
            config.blocked_countries,
            BTreeSet::from([String::from("CN"), String::from("RU")])
        );
        assert_eq!(
            config.whitelist_countries,
            BTreeSet::from([String::from("US")])
        );
        assert_eq!(config.rate_limit, 25);
        assert_eq!(config.rate_limit_window, 45);
        assert_eq!(config.endpoint_rate_limits["/api"], (7, 30));
        assert_eq!(
            config.block_cloud_providers,
            Some(BTreeSet::from([
                String::from("AWS"),
                String::from("AWS:!prod"),
                String::from("GCP"),
            ]))
        );
        assert_eq!(config.blocked_user_agents, vec![String::from("evil-agent")]);
        assert_eq!(
            outcome.rejected_user_agents.len(),
            1,
            "the unsafe pattern rejects with its reason"
        );
        assert!(!config.enable_penetration_detection);
        assert!(!config.enable_ip_banning);
        assert!(config.enable_rate_limiting);
        assert_eq!(
            config.auto_ban_threshold, 10,
            "the emergency halves 20 to 10"
        );
        assert_eq!(config.auto_ban_duration, 9_000);
        assert!(!config.enable_rate_limit_auto_ban);
        assert!(config.emergency_mode);
        assert_eq!(config.emergency_whitelist, vec![String::from("10.0.0.1")]);
        assert!(outcome.emergency_activated);
        assert_eq!(outcome.patterns, vec![String::from("union.*select")]);
    }

    #[test]
    fn the_application_without_rule_content_changes_nothing() {
        let mut config = SecurityConfig::default();
        let before = config.clone();
        let outcome = apply_to_config(&mut config, &rules());
        assert_eq!(config.blocked_countries, before.blocked_countries);
        assert_eq!(config.rate_limit, before.rate_limit);
        assert_eq!(config.emergency_mode, before.emergency_mode);
        assert_eq!(config.auto_ban_threshold, before.auto_ban_threshold);
        assert!(outcome.bans.is_empty());
        assert!(outcome.unbans.is_empty());
        assert!(outcome.patterns.is_empty());
        assert!(outcome.rejected_user_agents.is_empty());
        assert!(!outcome.emergency_activated);
    }

    #[test]
    fn the_emergency_threshold_never_reaches_zero() {
        let mut config = SecurityConfig {
            auto_ban_threshold: 1,
            ..SecurityConfig::default()
        };
        let mut r = rules();
        r.emergency_mode = true;
        let outcome = apply_to_config(&mut config, &r);
        assert_eq!(config.auto_ban_threshold, 1, "max(1, 1/2)");
        assert!(outcome.emergency_activated);
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    #[test]
    fn debug_roundtrip() {
        let mut r = DynamicRules {
            rule_id: String::from("rule-1"),
            version: 2,
            ..DynamicRules::default()
        };
        r.ip_blacklist = vec![String::from("192.0.2.1")];
        let v = serde_json::to_value(&r).expect("serializes");
        let back: DynamicRules = serde_json::from_value(v).expect("decodes");
        assert_eq!(back.rule_id, String::from("rule-1"));
        assert_eq!(back.ip_blacklist, vec![String::from("192.0.2.1")]);
    }

    #[test]
    fn a_wrong_typed_field_fails_the_decode() {
        let payload = serde_json::json!({ "version": "not-a-number" });
        let back: Result<DynamicRules, _> = serde_json::from_value(payload);
        assert!(back.is_err(), "a wrong-typed field is a decode error");
    }
}
