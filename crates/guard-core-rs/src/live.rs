//! The stages a dynamic rule can change, rebuilt from the live config.
//!
//! The reference mutates the one live `SecurityConfig` the checks read
//! (`guard_core/handlers/_dynamic_rule_application.py`), so a rule that
//! changes a rate limit, a country list, a blocked user agent, the emergency
//! mode or the ban knobs takes effect on the next request. The Rust adapters
//! build their stages once from the config, so [`Wiring::live`](crate::wiring::Wiring::live) hands them
//! this seam instead: a [`LiveContext`] over [`Wiring::live_config`](crate::wiring::Wiring::live_config) that an
//! adapter turns into a [`LiveCell`] with one `derive` closure, and reads per
//! request. The cell compares the fifteen fields a rule may change (the
//! dynamic-rule snapshot) against the live config, and rebuilds the derived
//! value only when one differs, so an unchanged config costs one read lock and
//! a field comparison.
//!
//! The recorded rate-limit windows, the ban store, the violation counters and
//! the cloud range table all survive a rebuild (they are shared handles). A
//! rebuild that fails (a delivery the validators rejected) keeps the previous
//! stages. A country list or cloud provider added by a rule when none was
//! configured at startup builds its stage over the geo handler and range table
//! the startup wiring owns: a rule cannot create a geolocation database or a
//! range refresh the config did not describe.

use std::sync::{Arc, RwLock};

use guard_core_engine::cloud_provider::{CloudIpTable, parse_cloud_selectors};
use guard_core_engine::geo::{GeoIpHandler, parse_country_lists};
use guard_core_engine::ip_ban::{IpBanConfig, IpBanManager};
use guard_core_engine::rate_limit::{RateLimitConfig, RateLimiter};
use guard_core_engine::security_config::SecurityConfig;
use guard_core_engine::user_agent::UserAgentFilter;

use crate::cloud_provider::{CloudProviderStage, CloudProviderStageConfig};
use crate::dynamic_rules::SnapshotConfig;
use crate::emergency_mode::{EmergencyModeStage, EmergencyModeStageConfig};
use crate::geo::{GeoStage, GeoStageConfig};
use crate::user_agent::{UserAgentStage, UserAgentStageConfig};
use crate::wiring::{WiringError, rate_limit_config};

/// The stages and knobs a dynamic rule can change, built from one config
/// state.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct LiveStages {
    /// `enable_penetration_detection`.
    pub penetration_detection: bool,
    /// The country stage, when country rules are set.
    pub geo: Option<GeoStage>,
    /// The cloud-provider stage, when providers are blocked.
    pub cloud: Option<CloudProviderStage>,
    /// The blocked-user-agent stage.
    pub user_agent: Option<UserAgentStage>,
    /// The emergency stage, when the mode or a whitelist is set.
    pub emergency: Option<EmergencyModeStage>,
    /// The rate limiter over the live limits (`enable_rate_limiting`
    /// included), sharing the recorded windows of the startup limiter.
    pub rate_limiter: RateLimiter,
    /// The rate-limit knobs the limiter was built from.
    pub rate_limit: RateLimitConfig,
    /// The auto-ban knobs (`enable_ip_banning` included).
    pub ip_ban: IpBanConfig,
    /// The shared ban store.
    pub bans: IpBanManager,
}

/// What a rebuild reuses from the startup wiring.
#[derive(Clone)]
pub struct LiveContext {
    config: Arc<RwLock<SecurityConfig>>,
    geo_handler: Option<Arc<dyn GeoIpHandler>>,
    cloud_table: Arc<CloudIpTable>,
    limiter: RateLimiter,
    bans: IpBanManager,
}

impl LiveContext {
    pub(crate) const fn new(
        config: Arc<RwLock<SecurityConfig>>,
        geo_handler: Option<Arc<dyn GeoIpHandler>>,
        cloud_table: Arc<CloudIpTable>,
        limiter: RateLimiter,
        bans: IpBanManager,
    ) -> Self {
        Self {
            config,
            geo_handler,
            cloud_table,
            limiter,
            bans,
        }
    }

    /// The live config handle (the one the dynamic-rule manager mutates).
    #[must_use]
    pub const fn config(&self) -> &Arc<RwLock<SecurityConfig>> {
        &self.config
    }

    /// The ban store the stages and the dynamic rules share.
    #[must_use]
    pub const fn bans(&self) -> &IpBanManager {
        &self.bans
    }

    /// Build the stages `config` describes.
    ///
    /// # Errors
    ///
    /// [`WiringError`] when a value is rejected (an unknown provider, an
    /// unsafe user-agent pattern, a zero limit).
    pub fn build(&self, config: &SecurityConfig) -> Result<LiveStages, WiringError> {
        let gate = parse_country_lists(&config.whitelist_countries, &config.blocked_countries);
        let geo = gate.has_rules().then(|| {
            GeoStage::new(GeoStageConfig {
                gate,
                handler: self.geo_handler.clone(),
                passive_mode: config.passive_mode,
            })
        });
        let cloud = match config
            .block_cloud_providers
            .as_ref()
            .filter(|providers| !providers.is_empty())
        {
            Some(providers) => Some(CloudProviderStage::new(CloudProviderStageConfig {
                block_cloud_providers: parse_cloud_selectors(providers)?,
                table: (*self.cloud_table).clone(),
                passive_mode: config.passive_mode,
            })),
            None => None,
        };
        let user_agent = if config.blocked_user_agents.is_empty() {
            None
        } else {
            Some(
                UserAgentStage::builder(UserAgentStageConfig {
                    // Every entry in the live config was already ReDoS
                    // validated (the startup wiring, or the dynamic-rule
                    // application), so the rebuild on the request path only
                    // compiles them.
                    blocked_user_agents: UserAgentFilter::from_trusted_patterns(
                        config.blocked_user_agents.iter().cloned(),
                    )?,
                    ip_ban: config.ip_ban_config(),
                    passive_mode: config.passive_mode,
                })
                .build()?,
            )
        };
        let emergency = if config.emergency_mode || !config.emergency_whitelist.is_empty() {
            Some(
                EmergencyModeStage::builder(EmergencyModeStageConfig {
                    emergency_mode: config.emergency_mode,
                    passive_mode: config.passive_mode,
                })
                .emergency_whitelist(config.emergency_whitelist.iter().cloned())
                .build()?,
            )
        } else {
            None
        };
        let rate_limit = rate_limit_config(config)?;
        Ok(LiveStages {
            penetration_detection: config.enable_penetration_detection,
            geo,
            cloud,
            user_agent,
            emergency,
            rate_limiter: self.limiter.with_config(rate_limit.clone())?,
            rate_limit,
            ip_ban: config.ip_ban_config(),
            bans: self.bans.clone(),
        })
    }

    /// A cell over `derive`: the value an adapter builds from the live
    /// stages, rebuilt when a rule changes them.
    ///
    /// # Errors
    ///
    /// [`WiringError`] when the current config cannot be built (the wiring
    /// already built the same state, so this is the defensive arm).
    pub fn cell<T, F>(&self, derive: F) -> Result<LiveCell<T>, WiringError>
    where
        F: Fn(&Arc<LiveStages>) -> T + Send + Sync + 'static,
    {
        let config = self.config.read().expect("live config");
        let stages = Arc::new(self.build(&config)?);
        let state = LiveState {
            snapshot: SnapshotConfig::capture(&config),
            value: Arc::new(derive(&stages)),
            stages,
        };
        drop(config);
        Ok(LiveCell {
            context: self.clone(),
            derive: Box::new(derive),
            state: RwLock::new(state),
        })
    }
}

type Derive<T> = Box<dyn Fn(&Arc<LiveStages>) -> T + Send + Sync>;

struct LiveState<T> {
    snapshot: SnapshotConfig,
    stages: Arc<LiveStages>,
    value: Arc<T>,
}

/// An adapter value derived from the live stages (see the module docs).
pub struct LiveCell<T> {
    context: LiveContext,
    derive: Derive<T>,
    state: RwLock<LiveState<T>>,
}

impl<T> LiveCell<T> {
    /// The current value: the cached one while the live config still matches
    /// what it was built from, a rebuilt one after a rule changed it (the
    /// previous one when the rebuild is rejected).
    ///
    /// # Panics
    ///
    /// When a lock was poisoned by a panicking rebuild.
    #[must_use]
    pub fn get(&self) -> Arc<T> {
        let Ok(config) = self.context.config.read() else {
            return Arc::clone(&self.state.read().expect("live state").value);
        };
        {
            let state = self.state.read().expect("live state");
            if state.snapshot.matches(&config) {
                return Arc::clone(&state.value);
            }
        }
        // Two requests that both saw the change rebuild twice in turn; the
        // result is the same and a rule change is rare.
        let mut state = self.state.write().expect("live state");
        // The snapshot advances even when the rebuild is rejected: the same
        // rejected state is not rebuilt (and re-rejected) on every request.
        state.snapshot = SnapshotConfig::capture(&config);
        if let Ok(stages) = self.context.build(&config) {
            let stages = Arc::new(stages);
            state.value = Arc::new((self.derive)(&stages));
            state.stages = stages;
        }
        Arc::clone(&state.value)
    }

    /// The stages the current value was derived from.
    ///
    /// # Panics
    ///
    /// When a lock was poisoned by a panicking rebuild.
    #[must_use]
    pub fn stages(&self) -> Arc<LiveStages> {
        let _current = self.get();
        Arc::clone(&self.state.read().expect("live state").stages)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    use super::*;
    use crate::wiring::Wiring;

    struct Germany;

    impl GeoIpHandler for Germany {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some("DE".to_owned())
        }
    }

    fn wired() -> (Wiring, LiveCell<LiveStages>) {
        let config = SecurityConfig {
            enable_redis: false,
            enable_rate_limiting: true,
            rate_limit: 3,
            geo_ip_handler: Some(Arc::new(Germany)),
            ..SecurityConfig::default()
        };
        let wiring = Wiring::from_security_config(&config).expect("wired");
        let cell = wiring
            .live
            .cell(|stages| LiveStages::clone(stages))
            .expect("cell");
        (wiring, cell)
    }

    fn mutate(wiring: &Wiring, change: impl FnOnce(&mut SecurityConfig)) {
        change(&mut wiring.live_config.write().expect("live config"));
    }

    #[test]
    fn an_unchanged_config_returns_the_cached_value() {
        let (_wiring, cell) = wired();
        assert!(Arc::ptr_eq(&cell.get(), &cell.get()));
    }

    #[test]
    fn a_rate_limit_change_reaches_the_rebuilt_limiter_and_keeps_the_windows() {
        let (wiring, cell) = wired();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let before = cell.get();
        assert_eq!(before.rate_limit.rate_limit, 3);
        for _ in 0..3 {
            assert!(before.rate_limiter.check(ip, None).allowed);
        }
        assert!(!before.rate_limiter.check(ip, None).allowed);

        mutate(&wiring, |config| config.rate_limit = 50);
        let after = cell.get();
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.rate_limit.rate_limit, 50);
        // The recorded window survived: 4 requests so far, limit now 50.
        assert!(after.rate_limiter.check(ip, None).allowed);
        assert_eq!(after.rate_limiter.tracked_windows(), 1);
    }

    #[test]
    fn country_agent_emergency_and_ban_changes_rebuild_their_stages() {
        let (wiring, cell) = wired();
        let before = cell.get();
        assert!(before.geo.is_none() && before.user_agent.is_none());
        assert!(before.emergency.is_none());

        mutate(&wiring, |config| {
            config.blocked_countries = BTreeSet::from(["DE".to_owned()]);
            config.blocked_user_agents = vec!["badbot".to_owned()];
            config.emergency_mode = true;
            config.enable_penetration_detection = false;
            config.auto_ban_threshold = 2;
        });
        let after = cell.get();
        let geo = after.geo.as_ref().expect("geo stage");
        assert!(
            geo.decide("203.0.113.9".parse().ok(), None).is_some(),
            "the new blocklist blocks DE"
        );
        assert!(after.user_agent.is_some());
        assert!(after.emergency.is_some());
        assert!(!after.penetration_detection);
        assert_eq!(after.ip_ban.auto_ban_threshold, 2);
    }

    #[test]
    fn a_rejected_rebuild_keeps_the_previous_value_and_is_not_retried() {
        let (wiring, cell) = wired();
        let before = cell.get();
        mutate(&wiring, |config| {
            config.block_cloud_providers = Some(BTreeSet::from(["nope".to_owned()]));
        });
        let kept = cell.get();
        assert!(Arc::ptr_eq(&before, &kept));
        assert!(Arc::ptr_eq(&kept, &cell.get()));
    }

    #[test]
    fn a_cloud_provider_rule_builds_the_stage_and_an_uncompilable_agent_is_rejected() {
        let (wiring, cell) = wired();
        mutate(&wiring, |config| {
            config.block_cloud_providers = Some(BTreeSet::from(["AWS".to_owned()]));
        });
        assert!(cell.get().cloud.is_some());
        let kept = cell.get();
        mutate(&wiring, |config| {
            config.blocked_user_agents = vec!["(".to_owned()];
        });
        assert!(Arc::ptr_eq(&kept, &cell.get()));
    }

    #[test]
    fn the_stages_accessor_follows_the_value() {
        let (wiring, cell) = wired();
        mutate(&wiring, |config| config.rate_limit = 9);
        assert_eq!(cell.stages().rate_limit.rate_limit, 9);
        assert_eq!(wiring.live.bans().banned_count(), 0);
    }

    #[test]
    fn a_poisoned_config_lock_serves_the_cached_value() {
        let (wiring, cell) = wired();
        let before = cell.get();
        let handle = Arc::clone(&wiring.live_config);
        let _ = std::thread::spawn(move || {
            let _guard = handle.write().expect("lock");
            panic!("poison the live config");
        })
        .join();
        assert!(Arc::ptr_eq(&before, &cell.get()));
        assert!(wiring.live.config().read().is_err());
    }
}
