//! The `DynamicRuleManager` port (`handlers/dynamic_rule_handler.py` +
//! `_dynamic_rule_snapshot.py`).
//!
//! The port carries the fetch-apply loop over the agent seam, the
//! versioning and expiry gates, the snapshot/restore of the config
//! fields, the last-known persistence, and the event emissions. The
//! reference drives an asyncio loop that polls
//! `agent_handler.get_dynamic_rules()` on `dynamic_rule_interval`
//! cadence, applies each newer rule onto the live `SecurityConfig`, and
//! restores the pre-rule snapshot when a rule expires. The port keeps
//! every decision the reference makes, on the crate's synchronous seam
//! idiom (no runtime lives here, the host drives the cadence - a std
//! thread, an async task, anything that calls
//! [`DynamicRuleManager::update_rules`]):
//!
//! - the rules fetch rides the [`TelemetryHandler`] sink (the composite
//!   fan-out's first-non-`None` answer - the reference's agent handler
//!   slot); the JSON payload decodes through the engine's
//!   `guard_core_engine::dynamic_rules::DynamicRules`;
//! - the applied config lives behind the manager's
//!   `Arc<RwLock<SecurityConfig>>`: the app builds its guard from this
//!   config handle, and the applied rules are observable to anything
//!   reading the same handle; the IP bans and unbans additionally land
//!   through the shared [`IpBanManager`] the pipeline consults, so a
//!   fetched rule's `ip_blacklist` feeds detection immediately;
//! - the suspicious-pattern additions land through the
//!   [`SusPatternsManager`] (`add_pattern`, the store's own validation);
//! - the last-known rules persist to
//!   [`SecurityConfig::dynamic_rules_cache_path`] (the reference's file
//!   store; the Redis store rides the same envelope under the `redis`
//!   feature through `TelemetryRedisStore`) and hydrate before the
//!   first poll, unexpired ones only;
//! - the events land through the same sink:
//!   `dynamic_rule_updated` (`rules_received`), `dynamic_rule_applied`
//!   (`rules_updated`), and `emergency_mode` (`emergency_lockdown`) -
//!   `ip_address = "system"`, `handler_name = "dynamic_rules"`, the
//!   reference metadata keys;
//! - [`DynamicRuleManager::rule_matcher`] answers the enricher's
//!   `RuleMatcher` closure (the reference `match_event` correlation).
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, RwLock};
//!
//! use guard_core_rs::dynamic_rules::DynamicRuleManager;
//!
//! let config = Arc::new(RwLock::new(
//!     guard_core_engine::security_config::SecurityConfig::default(),
//! ));
//! let manager = Arc::new(DynamicRuleManager::new(Arc::clone(&config)));
//!
//! // No rules applied yet: the identity is unset and the enricher
//! // matcher answers none.
//! assert!(manager.current_identity().is_none());
//! let event = guard_core_rs::events::SecurityEvent::new(
//!     "rate_limited",
//!     "192.0.2.1",
//!     "request_blocked",
//!     "limit",
//!     "rate_limit",
//! );
//! assert!(manager.rule_matcher()(&event).is_none());
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use guard_core_engine::dynamic_rules::{
    AppliedDynamicRules, DynamicRules, dump_last_known_rules_snapshot, expired_identity,
    has_expired, load_last_known_rules_snapshot, matches_event, should_update,
};
use guard_core_engine::ip_ban::IpBanManager;
use guard_core_engine::security_config::SecurityConfig;

use crate::composite::TelemetryHandler;
use crate::enrichment::RuleMatcher;
use crate::event_types::{
    EVENT_DYNAMIC_RULE_APPLIED, EVENT_DYNAMIC_RULE_UPDATED, EVENT_EMERGENCY_MODE,
};
use crate::events::SecurityEvent;
use crate::sus_patterns::SusPatternsManager;

/// `DYNAMIC_RULES_HANDLER_NAME`: the emitting handler on every manager
/// event.
pub const DYNAMIC_RULES_HANDLER_NAME: &str = "dynamic_rules";

/// The pre-rule config snapshot (`_SNAPSHOT_FIELDS`): the fifteen
/// fields a rule may mutate, captured before the first application and
/// restored when the rule expires.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names, clippy::struct_excessive_bools)]
struct SnapshotConfig {
    blocked_countries: std::collections::BTreeSet<String>,
    whitelist_countries: std::collections::BTreeSet<String>,
    rate_limit: u32,
    rate_limit_window: u64,
    endpoint_rate_limits: std::collections::BTreeMap<String, (u32, u64)>,
    block_cloud_providers: Option<std::collections::BTreeSet<String>>,
    blocked_user_agents: Vec<String>,
    enable_penetration_detection: bool,
    enable_ip_banning: bool,
    enable_rate_limiting: bool,
    emergency_mode: bool,
    emergency_whitelist: Vec<String>,
    auto_ban_threshold: u32,
    auto_ban_duration: u64,
    enable_rate_limit_auto_ban: bool,
}

impl SnapshotConfig {
    fn capture(config: &SecurityConfig) -> Self {
        Self {
            blocked_countries: config.blocked_countries.clone(),
            whitelist_countries: config.whitelist_countries.clone(),
            rate_limit: config.rate_limit,
            rate_limit_window: config.rate_limit_window,
            endpoint_rate_limits: config.endpoint_rate_limits.clone(),
            block_cloud_providers: config.block_cloud_providers.clone(),
            blocked_user_agents: config.blocked_user_agents.clone(),
            enable_penetration_detection: config.enable_penetration_detection,
            enable_ip_banning: config.enable_ip_banning,
            enable_rate_limiting: config.enable_rate_limiting,
            emergency_mode: config.emergency_mode,
            emergency_whitelist: config.emergency_whitelist.clone(),
            auto_ban_threshold: config.auto_ban_threshold,
            auto_ban_duration: config.auto_ban_duration,
            enable_rate_limit_auto_ban: config.enable_rate_limit_auto_ban,
        }
    }

    fn restore(self, config: &mut SecurityConfig) {
        config.blocked_countries = self.blocked_countries;
        config.whitelist_countries = self.whitelist_countries;
        config.rate_limit = self.rate_limit;
        config.rate_limit_window = self.rate_limit_window;
        config.endpoint_rate_limits = self.endpoint_rate_limits;
        config.block_cloud_providers = self.block_cloud_providers;
        config.blocked_user_agents = self.blocked_user_agents;
        config.enable_penetration_detection = self.enable_penetration_detection;
        config.enable_ip_banning = self.enable_ip_banning;
        config.enable_rate_limiting = self.enable_rate_limiting;
        config.emergency_mode = self.emergency_mode;
        config.emergency_whitelist = self.emergency_whitelist;
        config.auto_ban_threshold = self.auto_ban_threshold;
        config.auto_ban_duration = self.auto_ban_duration;
        config.enable_rate_limit_auto_ban = self.enable_rate_limit_auto_ban;
    }
}

#[derive(Default)]
struct ManagerState {
    current_rules: Option<DynamicRules>,
    last_update: Option<DateTime<Utc>>,
    last_skipped_expired: Option<(String, u64)>,
    base_snapshot: Option<SnapshotConfig>,
}

/// The reference `DynamicRuleManager`. Clone-safe (the state rides an
/// `Arc`); every poll is one [`DynamicRuleManager::update_rules`] call.
pub struct DynamicRuleManager {
    config: Arc<RwLock<SecurityConfig>>,
    sink: Option<Arc<dyn TelemetryHandler>>,
    bans: Option<IpBanManager>,
    patterns: Option<Arc<SusPatternsManager>>,
    cache_path: Option<PathBuf>,
    validation_cache: Option<Arc<guard_core_engine::redos::validation_cache::ValidationCache>>,
    clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    state: Mutex<ManagerState>,
}

impl core::fmt::Debug for DynamicRuleManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DynamicRuleManager")
            .field("sink", &self.sink.is_some())
            .field("bans", &self.bans.is_some())
            .field("patterns", &self.patterns.is_some())
            .field("cache_path", &self.cache_path)
            .finish_non_exhaustive()
    }
}

/// One poll's outcome (the reference's log lines, carried as data).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateOutcome {
    /// The applied rule identity when a rule landed.
    pub applied: Option<(String, u64)>,
    /// An already-expired rule was ignored (warned once per identity).
    pub skipped_expired: bool,
    /// A fetched rule was stale (the version gate held).
    pub stale: bool,
    /// The current rule expired and the base snapshot restored.
    pub expired_restored: bool,
    /// The bans the application produced (applied through the ban
    /// manager when one is wired).
    pub bans_applied: usize,
    /// The unparseable ban addresses (reported, skipped).
    pub unparseable_bans: Vec<String>,
    /// The user agent patterns the ReDoS validator rejected.
    pub rejected_user_agents: Vec<(String, String)>,
}

impl DynamicRuleManager {
    /// The manager over the live config handle; the collaborators
    /// attach through the builders.
    #[must_use]
    pub fn new(config: Arc<RwLock<SecurityConfig>>) -> Self {
        let cache_path = config
            .read()
            .map(|config| config.dynamic_rules_cache_path.clone())
            .unwrap_or_default();
        Self {
            config,
            sink: None,
            bans: None,
            patterns: None,
            cache_path,
            validation_cache: None,
            clock: Arc::new(chrono::Utc::now),
            state: Mutex::new(ManagerState::default()),
        }
    }

    /// The agent seam (the composite; the reference `initialize_agent`).
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn TelemetryHandler>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The shared ban manager (the `ip_ban_manager` half of the
    /// reference application: rules ban and unban through the same state
    /// the pipeline consults).
    #[must_use]
    pub fn with_bans(mut self, bans: IpBanManager) -> Self {
        self.bans = Some(bans);
        self
    }

    /// The pattern store (the `sus_patterns_handler` half: rule
    /// patterns add through the store's own validation); the `Arc`
    /// shares the registry with the detection side.
    #[must_use]
    pub fn with_patterns(mut self, patterns: Arc<SusPatternsManager>) -> Self {
        self.patterns = Some(patterns);
        self
    }

    /// Override the clock (deterministic expiry in tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// The disk-backed pattern-validation cache
    /// (`detection_pattern_validation_cache_path`): every poll's
    /// user-agent ReDoS validation consults the cache for the empirical
    /// cost verdict, so repeated boots and polls reuse prior
    /// certifications instead of re-timing every fetched pattern. The
    /// load outcome rides [`guard_core_engine::redos::validation_cache::ValidationCache::outcome`] (the reference's
    /// log-once warnings, surfaced as data).
    #[must_use]
    pub fn with_validation_cache_path(mut self, path: &std::path::Path) -> Self {
        self.validation_cache = Some(Arc::new(
            guard_core_engine::redos::validation_cache::ValidationCache::load(path),
        ));
        self
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// The current rules identity, `None` before the first application.
    ///
    /// # Errors
    ///
    /// Never; the state lock is fair-queued and unpoisoned.
    pub fn current_identity(&self) -> Option<(String, u64)> {
        let state = self.state.lock().expect("manager state");
        state
            .current_rules
            .as_ref()
            .map(|rules| (rules.rule_id.clone(), rules.version))
    }

    /// The last successful application time.
    ///
    /// # Errors
    ///
    /// Never; the state lock is fair-queued and unpoisoned.
    pub fn last_update(&self) -> Option<DateTime<Utc>> {
        self.state.lock().expect("manager state").last_update
    }

    /// The enricher correlation (`match_event`): the closure reads the
    /// live current rules.
    #[must_use]
    // The closure's state guard holds across its match arms only - the
    // closure returns from under it, the tightening is the shape.
    #[allow(clippy::significant_drop_tightening)]
    pub fn rule_matcher(self: &Arc<Self>) -> RuleMatcher {
        let manager = Arc::clone(self);
        Arc::new(move |event: &SecurityEvent| {
            let state = manager.state.lock().expect("manager state");
            let rules = state.current_rules.as_ref()?;
            matches_event(
                rules,
                Some(event.ip_address.as_str()),
                event.country.as_deref(),
                event.event_type.as_str(),
            )
            .map(|(rule_id, version)| (rule_id, version.to_string()))
        })
    }

    /// `_hydrate_last_known_rules`: the last-known rules from the cache
    /// file, applied before the first poll (unexpired ones only).
    pub fn hydrate_last_known_rules(&self) -> Result<Option<(String, u64)>, SnapshotLoadFailure> {
        let Some(path) = &self.cache_path else {
            return Ok(None);
        };
        let payload = std::fs::read_to_string(path).map_err(|_| SnapshotLoadFailure {
            reason: String::from("no cache file"),
        })?;
        let rules =
            load_last_known_rules_snapshot(&payload).map_err(|error| SnapshotLoadFailure {
                reason: error.to_string(),
            })?;
        if has_expired(&rules, self.now()) {
            return Err(SnapshotLoadFailure {
                reason: format!(
                    "Discarding expired last-known dynamic rules {} v{}",
                    rules.rule_id, rules.version
                ),
            });
        }
        self.apply_rule(&rules);
        let identity = (rules.rule_id.clone(), rules.version);
        {
            let mut state = self.state.lock().expect("manager state");
            state.current_rules = Some(rules);
            state.last_update = Some(self.now());
        }
        Ok(Some(identity))
    }

    /// `update_rules`: one poll cycle - the expiry check, the fetch,
    /// the gates, the application, the persistence, and the events.
    pub fn update_rules(&self) -> UpdateOutcome {
        let enabled = self
            .config
            .read()
            .is_ok_and(|config| config.enable_dynamic_rules);
        let Some(sink) = self.sink.as_ref().filter(|_| enabled) else {
            return UpdateOutcome::default();
        };
        self.expire_current_rule();
        let mut outcome = UpdateOutcome::default();

        let Ok(Some(payload)) = sink.get_dynamic_rules() else {
            return outcome;
        };
        let Ok(rules) = serde_json::from_value::<DynamicRules>(payload) else {
            return outcome;
        };

        // `_reject_if_already_expired`: the de-duplicated warning.
        {
            let mut state = self.state.lock().expect("manager state");
            if expired_identity(&mut state.last_skipped_expired, &rules, self.now()) {
                outcome.skipped_expired = true;
                return outcome;
            }
        }

        // `_should_update_rules`: the version gate.
        {
            let state = self.state.lock().expect("manager state");
            if !should_update(state.current_rules.as_ref(), &rules) {
                outcome.stale = true;
                return outcome;
            }
        }

        self.send_rule_event(
            EVENT_DYNAMIC_RULE_UPDATED,
            "rules_received",
            &format!(
                "Received updated rules {} v{}",
                rules.rule_id, rules.version
            ),
            serde_json::json!({
                "rule_id": rules.rule_id,
                "version": rules.version,
                "previous_version": self.current_version(),
            }),
        );

        let applied = self.apply_rule(&rules);
        outcome.applied = Some((rules.rule_id.clone(), rules.version));
        outcome.bans_applied = applied.bans.len();
        outcome.unparseable_bans = applied.unparseable_bans;
        outcome.rejected_user_agents = applied.rejected_user_agents;

        self.persist_last_known(&rules);
        self.send_rule_event(
            EVENT_DYNAMIC_RULE_APPLIED,
            "rules_updated",
            &format!("Applied dynamic rules {} v{}", rules.rule_id, rules.version),
            serde_json::json!({
                "rule_id": rules.rule_id,
                "version": rules.version,
                "ip_bans": rules.ip_blacklist.len(),
                "country_blocks": rules.blocked_countries.len(),
                "emergency_mode": rules.emergency_mode,
            }),
        );

        let mut state = self.state.lock().expect("manager state");
        state.current_rules = Some(rules);
        state.last_update = Some(self.now());
        outcome
    }

    /// `_check_rule_expiry`: an expired current rule restores the base
    /// snapshot and clears the active rule.
    pub fn expire_current_rule(&self) -> bool {
        let expired = {
            let state = self.state.lock().expect("manager state");
            state
                .current_rules
                .as_ref()
                .is_some_and(|rules| has_expired(rules, self.now()))
        };
        if !expired {
            return false;
        }
        let mut state = self.state.lock().expect("manager state");
        // The base snapshot restores when one was captured (the first
        // application); a hydrated-from-cache rule restores nothing (the
        // reference `_check_rule_expiry` guards the same way).
        if let Some(base) = state.base_snapshot.take()
            && let Ok(mut config) = self.config.write()
        {
            base.restore(&mut config);
        }
        state.current_rules = None;
        true
    }

    fn current_version(&self) -> u64 {
        self.state
            .lock()
            .expect("manager state")
            .current_rules
            .as_ref()
            .map_or(0, |rules| rules.version)
    }

    /// `_apply_rules` + the stateful lands: the snapshot capture (before
    /// the first rule), the config application, the bans and unbans
    /// through the shared manager, the patterns through the store.
    fn apply_rule(&self, rules: &DynamicRules) -> AppliedDynamicRules {
        let outcome =
            self.config
                .write()
                .ok()
                .map_or_else(AppliedDynamicRules::default, |mut config| {
                    // `_capture_active_base_snapshot`: only before the first
                    // rule lands.
                    {
                        let mut state = self.state.lock().expect("manager state");
                        if state.current_rules.is_none() && state.base_snapshot.is_none() {
                            state.base_snapshot = Some(SnapshotConfig::capture(&config));
                        }
                    }
                    guard_core_engine::dynamic_rules::apply_to_config_with_validation_cache(
                        &mut config,
                        rules,
                        self.validation_cache.as_deref(),
                    )
                });
        if let Some(bans) = self.bans.as_ref() {
            for (ip, duration) in &outcome.bans {
                let _applied = bans.ban_ip(*ip, *duration, "dynamic_rule");
            }
            for ip in &outcome.unbans {
                bans.unban(*ip);
            }
        }
        if let Some(patterns) = self.patterns.as_ref() {
            for pattern in &outcome.patterns {
                let _ = patterns.add_pattern(pattern);
            }
        }
        if outcome.emergency_activated {
            self.send_rule_event(
                EVENT_EMERGENCY_MODE,
                "emergency_lockdown",
                "[EMERGENCY MODE] activated via dynamic rules",
                serde_json::json!({
                    "whitelist_count": rules.emergency_whitelist.len(),
                    "whitelist": rules.emergency_whitelist.iter().take(10).collect::<Vec<_>>(),
                }),
            );
        }
        outcome
    }

    /// `_persist_last_known_rules`: the versioned envelope into the
    /// cache path (the reference's file store).
    fn persist_last_known(&self, rules: &DynamicRules) {
        let Some(path) = &self.cache_path else {
            return;
        };
        if let Ok(payload) = dump_last_known_rules_snapshot(rules)
            && let Some(parent) = path.parent()
        {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::write(path, payload);
        }
    }

    fn send_rule_event(
        &self,
        event_type: &str,
        action_taken: &str,
        reason: &str,
        metadata: serde_json::Value,
    ) {
        if let Some(sink) = self.sink.as_ref() {
            let mut event = SecurityEvent::new(
                event_type,
                "system",
                action_taken,
                reason,
                DYNAMIC_RULES_HANDLER_NAME,
            );
            if let serde_json::Value::Object(map) = metadata {
                event.metadata = map;
            }
            let _ = sink.send_event(&event);
        }
    }
}

/// A last-known hydration failure (the reference logs these and runs
/// on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotLoadFailure {
    /// What failed.
    pub reason: String,
}

impl core::fmt::Display for SnapshotLoadFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "last-known rules hydration: {}", self.reason)
    }
}

impl std::error::Error for SnapshotLoadFailure {}

#[cfg(test)]
mod dynamic_rule_manager_tests {
    use super::*;
    use crate::composite::{TelemetryError, TelemetryRedisStore};
    use crate::event_types::{
        EVENT_DYNAMIC_RULE_APPLIED, EVENT_DYNAMIC_RULE_UPDATED, EVENT_EMERGENCY_MODE,
    };
    use guard_core_engine::distributed::StoreError;

    fn rules() -> DynamicRules {
        DynamicRules {
            rule_id: String::from("rule-1"),
            version: 2,
            ..DynamicRules::default()
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, secs, 0)
            .single()
            .expect("valid time")
    }

    /// A scripted sink: the rules payload, the events, and the health
    /// answer all record.
    struct ScriptedSink {
        events: Mutex<Vec<SecurityEvent>>,
        rules: Mutex<Vec<Option<serde_json::Value>>>,
    }

    impl ScriptedSink {
        fn new(rules: Vec<Option<serde_json::Value>>) -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                rules: Mutex::new(rules),
            }
        }

        fn events(&self) -> Vec<SecurityEvent> {
            self.events.lock().expect("events").clone()
        }
    }

    impl TelemetryHandler for ScriptedSink {
        fn handler_name(&self) -> &'static str {
            "ScriptedSink"
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
            self.events.lock().expect("events").push(event.clone());
            Ok(())
        }

        fn send_metric(
            &self,
            _metric: &crate::metrics::SecurityMetric,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
            let mut answers = self.rules.lock().expect("rules");
            Ok(answers.pop().unwrap_or(None))
        }

        fn health_check(&self) -> bool {
            true
        }
    }

    /// The minimal sink that never carries rules (the default paths).
    struct EmptySink;

    impl TelemetryHandler for EmptySink {
        fn handler_name(&self) -> &'static str {
            "EmptySink"
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_metric(
            &self,
            _metric: &crate::metrics::SecurityMetric,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn health_check(&self) -> bool {
            true
        }
    }

    /// A sink whose rules fetch fails (the composite's failure shape).
    struct FailingRulesSink;

    impl TelemetryHandler for FailingRulesSink {
        fn handler_name(&self) -> &'static str {
            "FailingRulesSink"
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_metric(
            &self,
            _metric: &crate::metrics::SecurityMetric,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
            Err(TelemetryError(String::from("rules fetch blew up")))
        }

        fn health_check(&self) -> bool {
            false
        }
    }

    /// A malformed payload sink (the decode arm).
    struct GarbageSink;

    impl TelemetryHandler for GarbageSink {
        fn handler_name(&self) -> &'static str {
            "GarbageSink"
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_metric(
            &self,
            _metric: &crate::metrics::SecurityMetric,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
            Ok(Some(serde_json::json!({"rule_id": 42})))
        }

        fn health_check(&self) -> bool {
            true
        }
    }

    struct NoopStore;

    impl TelemetryRedisStore for NoopStore {
        fn get_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
        ) -> Result<Option<String>, StoreError> {
            Ok(None)
        }

        fn set_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
            _value: &str,
            _ttl_seconds: Option<u64>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn manager_with(
        sink: Arc<dyn TelemetryHandler>,
    ) -> (Arc<DynamicRuleManager>, Arc<RwLock<SecurityConfig>>) {
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let manager = Arc::new(DynamicRuleManager::new(Arc::clone(&config)).with_sink(sink));
        (manager, config)
    }

    #[test]
    fn the_validation_cache_path_persists_pattern_certifications() {
        // A rule set with a blocked user-agent pattern: the poll's
        // ReDoS validation consults the disk cache and the certification
        // persists for the next boot or poll.
        let mut payload = rules();
        payload.blocked_user_agents = vec![String::from("^bad-bot-\\d+$")];
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&payload).expect("serializes"),
        )]));
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let dir =
            std::env::temp_dir().join(format!("guard-dyn-validation-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("validation-cache.json");

        let manager = DynamicRuleManager::new(Arc::clone(&config))
            .with_sink(sink)
            .with_validation_cache_path(&cache_path);
        manager.update_rules();

        assert!(cache_path.is_file(), "the pattern certification persisted");
        let reloaded =
            guard_core_engine::redos::validation_cache::ValidationCache::load(&cache_path);
        assert_eq!(
            reloaded.outcome(),
            &guard_core_engine::redos::validation_cache::LoadOutcome::Loaded {
                foreign_versions_dropped: 0
            }
        );
        assert!(
            reloaded.get("^bad-bot-\\d+$", true).is_some(),
            "the fetched pattern's verdict is cached"
        );
        // The validated pattern landed on the live config.
        let applied = config.read().expect("config").blocked_user_agents.clone();
        assert_eq!(applied, vec![String::from("^bad-bot-\\d+$")]);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn an_unwired_manager_polls_nothing() {
        let config = Arc::new(RwLock::new(SecurityConfig::default()));
        let manager = DynamicRuleManager::new(Arc::clone(&config));
        let outcome = manager.update_rules();
        assert_eq!(outcome, UpdateOutcome::default());
        assert!(manager.current_identity().is_none());
        assert!(manager.last_update().is_none());
        let debug = format!("{manager:?}");
        assert!(debug.contains("sink: false"));

        // The enable gate: a wired sink with the flag off also skips.
        let off_config = Arc::new(RwLock::new(SecurityConfig::default()));
        let disabled = DynamicRuleManager::new(off_config).with_sink(Arc::new(EmptySink));
        assert_eq!(disabled.update_rules(), UpdateOutcome::default());
    }

    #[test]
    fn a_full_poll_applies_gates_persists_and_emits() {
        let mut r = rules();
        r.ip_blacklist = vec![String::from("192.0.2.1")];
        r.emergency_mode = true;
        r.emergency_whitelist = vec![String::from("10.0.0.9")];
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let (manager, config) = manager_with(sink.clone());

        let outcome = manager.update_rules();
        assert_eq!(outcome.applied, Some((String::from("rule-1"), 2)));
        assert_eq!(outcome.bans_applied, 1);
        assert!(outcome.unparseable_bans.is_empty());
        assert!(!outcome.skipped_expired);
        let (blocked_empty, emergency) = {
            let config = config.read().expect("config");
            (config.blocked_countries.is_empty(), config.emergency_mode)
        };
        assert!(blocked_empty);
        assert!(emergency);
        assert_eq!(
            manager.current_identity(),
            Some((String::from("rule-1"), 2))
        );
        assert!(manager.last_update().is_some());

        let events = sink.events();
        let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(types.contains(&EVENT_DYNAMIC_RULE_UPDATED));
        assert!(types.contains(&EVENT_DYNAMIC_RULE_APPLIED));
        assert!(types.contains(&EVENT_EMERGENCY_MODE));
        let received = events
            .iter()
            .find(|e| e.event_type == EVENT_DYNAMIC_RULE_UPDATED)
            .expect("received event");
        assert_eq!(received.ip_address, "system");
        assert_eq!(received.handler_name.as_deref(), Some("dynamic_rules"));
        assert_eq!(received.action_taken, "rules_received");
        assert_eq!(received.metadata["rule_id"], "rule-1");
        assert_eq!(received.metadata["previous_version"], 0);
    }

    #[test]
    fn the_version_gate_holds_stale_replays_and_the_no_rules_answer_is_a_noop() {
        let mut r = rules();
        r.ip_blacklist = vec![String::from("192.0.2.1")];
        let payload = serde_json::to_value(&r).expect("serializes");
        // The pop order is LIFO: the stale replay answers first, then the
        // fresh rule, then the none.
        let sink = Arc::new(ScriptedSink::new(vec![
            None,
            Some(payload.clone()),
            Some(payload),
        ]));
        let (manager, _config) = manager_with(sink);

        let first = manager.update_rules();
        assert_eq!(first.applied, Some((String::from("rule-1"), 2)));
        let stale = manager.update_rules();
        assert!(stale.stale);
        assert!(stale.applied.is_none());
        assert_eq!(stale, stale, "the outcome stays comparable");
        let drained = manager.update_rules();
        assert!(drained.applied.is_none());
        assert!(!drained.stale);
    }

    #[test]
    fn the_expired_and_garbage_and_failing_arms_report_honestly() {
        let mut expiring = rules();
        expiring.expires_at = Some(at(500));
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&expiring).expect("serializes"),
        )]));
        let (manager, _config) = manager_with(sink);
        let outcome = manager.update_rules();
        assert!(outcome.skipped_expired);
        assert!(outcome.applied.is_none());

        let (garbage, _config) = manager_with(Arc::new(GarbageSink));
        assert!(garbage.update_rules().applied.is_none());

        let (failing, _config) = manager_with(Arc::new(FailingRulesSink));
        assert!(failing.update_rules().applied.is_none());

        // The failing and garbage sinks answer their full surface (the
        // manager only drives send_event and the rules fetch; the rest
        // rides the composite).
        let failing_sink = FailingRulesSink;
        assert_eq!(failing_sink.handler_name(), "FailingRulesSink");
        failing_sink.start().expect("start");
        failing_sink.stop().expect("stop");
        failing_sink
            .send_event(&SecurityEvent::new("x", "ip", "a", "r", "h"))
            .expect("send");
        let metric = crate::metrics::SecurityMetric {
            timestamp: std::time::SystemTime::now(),
            metric_type: String::from("request_count"),
            value: 1.0,
            endpoint: None,
            tags: std::collections::BTreeMap::new(),
        };
        failing_sink.send_metric(&metric).expect("send metric");
        assert!(!failing_sink.health_check());

        let garbage_sink = GarbageSink;
        assert_eq!(garbage_sink.handler_name(), "GarbageSink");
        garbage_sink.start().expect("start");
        garbage_sink.stop().expect("stop");
        garbage_sink
            .send_event(&SecurityEvent::new("x", "ip", "a", "r", "h"))
            .expect("send");
        garbage_sink.send_metric(&metric).expect("send metric");
        assert!(garbage_sink.health_check());
    }

    #[test]
    fn the_second_rule_identity_and_the_received_event_previous_version_track() {
        let first = rules();
        let mut second = rules();
        second.rule_id = String::from("rule-2");
        second.version = 9;
        let sink = Arc::new(ScriptedSink::new(vec![
            Some(serde_json::to_value(&second).expect("serializes")),
            Some(serde_json::to_value(&first).expect("serializes")),
        ]));
        let (manager, _config) = manager_with(sink.clone());
        manager.update_rules();
        let events = sink.events();
        let applied = events
            .iter()
            .find(|e| e.event_type == EVENT_DYNAMIC_RULE_APPLIED)
            .expect("applied");
        assert_eq!(applied.metadata["ip_bans"], 0);
        assert_eq!(applied.metadata["country_blocks"], 0);
        assert_eq!(applied.metadata["emergency_mode"], false);

        manager.update_rules();
        let events = sink.events();
        let received = events
            .iter()
            .rev()
            .find(|e| e.event_type == EVENT_DYNAMIC_RULE_UPDATED)
            .expect("second received");
        assert_eq!(received.metadata["previous_version"], 2);
        assert_eq!(
            manager.current_identity(),
            Some((String::from("rule-2"), 9))
        );
    }

    #[test]
    fn the_expiry_restores_the_base_snapshot() {
        let mut r = rules();
        r.blocked_countries = vec![String::from("CN")];
        r.global_rate_limit = Some(99);
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let manager = Arc::new(DynamicRuleManager::new(Arc::clone(&config)).with_sink(sink));
        manager.update_rules();
        let (countries, limit) = {
            let config = config.read().expect("config");
            (config.blocked_countries.clone(), config.rate_limit)
        };
        assert_eq!(
            countries,
            std::collections::BTreeSet::from([String::from("CN")])
        );
        assert_eq!(limit, 99);
        assert!(!manager.expire_current_rule(), "nothing expired yet");

        // Advance the clock past the (absent) expiry: the rule has no
        // expires_at, so the expiry gate never fires; a re-set rule with
        // a deadline does.
        let mut expiring = rules();
        expiring.rule_id = String::from("rule-exp");
        expiring.version = 3;
        expiring.blocked_countries = vec![String::from("RU")];
        expiring.expires_at = Some(at(1));
        manager.state.lock().expect("state").current_rules = Some(expiring);
        assert!(manager.expire_current_rule());
        let (countries_empty, limit) = {
            let config = config.read().expect("config");
            (config.blocked_countries.is_empty(), config.rate_limit)
        };
        assert!(countries_empty, "the base snapshot restored");
        assert_eq!(
            limit,
            SecurityConfig::default().rate_limit,
            "the reference default restored"
        );
        assert!(manager.current_identity().is_none());
    }

    #[test]
    fn the_bans_and_patterns_land_through_the_shared_seams() {
        let mut r = rules();
        r.ip_blacklist = vec![String::from("192.0.2.77")];
        r.suspicious_patterns = vec![String::from("union.*select")];
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let bans = IpBanManager::new();
        let patterns = Arc::new(crate::sus_patterns::SusPatternsManager::new());
        let manager = Arc::new(
            DynamicRuleManager::new(Arc::clone(&config))
                .with_sink(sink)
                .with_bans(bans.clone())
                .with_patterns(Arc::clone(&patterns)),
        );
        let outcome = manager.update_rules();
        assert_eq!(outcome.bans_applied, 1);
        assert!(
            bans.is_banned("192.0.2.77".parse().expect("ip")),
            "the rule ban feeds the shared ban state the pipeline reads"
        );
        assert!(
            patterns
                .get_custom_patterns()
                .contains(&String::from("union.*select"))
        );
    }

    #[test]
    fn the_matcher_correlates_the_current_rules() {
        let mut r = rules();
        r.ip_blacklist = vec![String::from("192.0.2.1")];
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let (manager, _config) = manager_with(sink);
        manager.update_rules();
        let rule_matcher = manager.rule_matcher();
        let event = SecurityEvent::new("rate_limited", "192.0.2.1", "x", "y", "m");
        let correlated = rule_matcher(&event).expect("correlates");
        assert_eq!(correlated, (String::from("rule-1"), String::from("2")));

        let miss = SecurityEvent::new("rate_limited", "192.0.2.9", "x", "y", "m");
        assert!(rule_matcher(&miss).is_none());
    }

    #[test]
    fn the_last_known_rules_persist_and_hydrate_through_the_cache_path() {
        let dir = std::env::temp_dir().join(format!("guard-dyn-rules-{}", std::process::id()));
        let path = dir.join("nested/cache.json");
        let mut r = rules();
        r.blocked_countries = vec![String::from("CN")];

        let config = Arc::new(RwLock::new(SecurityConfig {
            dynamic_rules_cache_path: Some(path.clone()),
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let manager = DynamicRuleManager::new(Arc::clone(&config)).with_sink(sink);
        manager.update_rules();
        assert!(path.exists(), "the envelope landed");

        // A fresh manager hydrates from the file before any poll.
        let hydrated_config = Arc::new(RwLock::new(SecurityConfig {
            dynamic_rules_cache_path: Some(path.clone()),
            ..SecurityConfig::default()
        }));
        let hydrated = DynamicRuleManager::new(Arc::clone(&hydrated_config));
        let identity = hydrated.hydrate_last_known_rules().expect("hydrates");
        assert_eq!(identity, Some((String::from("rule-1"), 2)));
        assert_eq!(
            hydrated_config.read().expect("config").blocked_countries,
            std::collections::BTreeSet::from([String::from("CN")])
        );

        // An expired snapshot refuses to hydrate.
        let expired = DynamicRules {
            expires_at: Some(at(1)),
            ..r
        };
        std::fs::write(
            &path,
            dump_last_known_rules_snapshot(&expired).expect("dumps"),
        )
        .expect("writes");
        let refused = DynamicRuleManager::new(Arc::clone(&hydrated_config));
        let failure = refused.hydrate_last_known_rules().expect_err("refuses");
        assert!(failure.reason.contains("Discarding expired"));

        // A garbage snapshot reports the decode failure.
        std::fs::write(&path, "not json").expect("writes");
        let decode = DynamicRuleManager::new(Arc::clone(&hydrated_config));
        let failure = decode.hydrate_last_known_rules().expect_err("refuses");
        assert!(failure.reason.contains("snapshot decode"));

        // A missing file reports the load failure; a config without a
        // cache path answers none.
        std::fs::remove_file(&path).expect("removes");
        let missing = DynamicRuleManager::new(Arc::clone(&hydrated_config));
        assert_eq!(
            missing.hydrate_last_known_rules(),
            Err(SnapshotLoadFailure {
                reason: String::from("no cache file")
            })
        );
        let no_path = DynamicRuleManager::new(Arc::new(RwLock::new(SecurityConfig::default())));
        assert_eq!(no_path.hydrate_last_known_rules(), Ok(None));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_frozen_clock_drives_the_expiry_gate_deterministically() {
        let mut r = rules();
        r.expires_at = Some(at(2_000));
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let manager = DynamicRuleManager::new(Arc::clone(&config))
            .with_sink(sink)
            .with_clock(Arc::new(|| at(1_000)));
        manager.update_rules();
        assert_eq!(
            manager.current_identity(),
            Some((String::from("rule-1"), 2))
        );
        assert!(
            !manager.expire_current_rule(),
            "at t=1000 the rule (expires 2000) is alive"
        );
    }

    #[test]
    fn the_enabled_but_sinkless_manager_polls_nothing() {
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let manager = DynamicRuleManager::new(config);
        assert_eq!(manager.update_rules(), UpdateOutcome::default());
    }

    #[test]
    fn the_whitelist_arm_unbans_through_the_shared_manager() {
        let mut r = rules();
        r.ip_whitelist = vec![String::from("192.0.2.55")];
        let sink = Arc::new(ScriptedSink::new(vec![Some(
            serde_json::to_value(&r).expect("serializes"),
        )]));
        let config = Arc::new(RwLock::new(SecurityConfig {
            enable_dynamic_rules: true,
            ..SecurityConfig::default()
        }));
        let bans = IpBanManager::new();
        let banned_ip: std::net::IpAddr = "192.0.2.55".parse().expect("ip");
        let was_banned = bans.ban_ip(banned_ip, 9_000, "pre-rule");
        assert!(was_banned.is_ok());
        assert!(bans.is_banned(banned_ip));
        let manager = DynamicRuleManager::new(config)
            .with_sink(sink)
            .with_bans(bans.clone());
        let outcome = manager.update_rules();
        assert_eq!(outcome.applied, Some((String::from("rule-1"), 2)));
        assert!(
            !bans.is_banned(banned_ip),
            "the rule whitelist unbans through the shared state"
        );
    }

    #[test]
    fn the_hydrated_emergency_rule_emits_through_the_absent_sink() {
        let dir = std::env::temp_dir().join(format!("guard-dyn-emerg-{}", std::process::id()));
        let path = dir.join("cache.json");
        let mut r = rules();
        r.emergency_mode = true;
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(&path, dump_last_known_rules_snapshot(&r).expect("dumps")).expect("writes");
        let config = Arc::new(RwLock::new(SecurityConfig {
            dynamic_rules_cache_path: Some(path),
            ..SecurityConfig::default()
        }));
        // No sink wired: the emergency emission is the None arm.
        let manager = DynamicRuleManager::new(Arc::clone(&config));
        assert!(manager.hydrate_last_known_rules().is_ok());
        assert!(config.read().expect("config").emergency_mode);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_scripted_and_empty_sinks_answer_every_surface() {
        let scripted = Arc::new(ScriptedSink::new(vec![None]));
        assert_eq!(scripted.handler_name(), "ScriptedSink");
        scripted.start().expect("start");
        scripted.stop().expect("stop");
        let event = SecurityEvent::new("rate_limited", "192.0.2.1", "x", "y", "m");
        scripted.send_event(&event).expect("send");
        let metric = crate::metrics::SecurityMetric {
            timestamp: std::time::SystemTime::now(),
            metric_type: String::from("request_count"),
            value: 1.0,
            endpoint: None,
            tags: std::collections::BTreeMap::new(),
        };
        scripted.send_metric(&metric).expect("send metric");
        assert!(scripted.health_check());

        let empty = Arc::new(EmptySink);
        assert_eq!(empty.handler_name(), "EmptySink");
        empty.start().expect("start");
        empty.stop().expect("stop");
        empty.send_event(&event).expect("send");
        empty.send_metric(&metric).expect("send metric");
        assert!(empty.health_check());
    }

    #[test]
    fn the_failure_shape_and_the_store_default_render() {
        let failure = SnapshotLoadFailure {
            reason: String::from("boom"),
        };
        assert_eq!(failure.to_string(), "last-known rules hydration: boom");
        assert_eq!(NoopStore.get_key("p", "ns", "k"), Ok(None));
        assert_eq!(NoopStore.set_key("p", "ns", "k", "v", None), Ok(()));
    }
}
