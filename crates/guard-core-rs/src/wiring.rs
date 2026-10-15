//! The one `SecurityConfig` to pipeline mapping the adapters share.
//!
//! Every adapter (tower, axum, actix, rocket) used to map the config
//! field by field on its own and each dropped a different subset.
//! [`Wiring::from_security_config`] is the single mapping: it builds every
//! stage, store and hook the config describes, and an adapter only installs
//! the parts on its own builder. The reference is the Python engine's
//! `SecurityConfig` plus its handler initialization.
//!
//! # Where every field lands
//!
//! | Field(s) | Lands in |
//! |---|---|
//! | `detection_max_content_length`, `detection_max_body_inspect_bytes`, `detection_preserve_attack_patterns`, `detection_semantic_threshold`, `detection_threat_score_threshold`, `detection_binary_min_run_length`, `detection_max_scan_values`, `detection_max_scan_chars`, `detection_max_json_depth` | [`Wiring::detect`] |
//! | `excluded_detection_headers`, `excluded_semantic_detection_headers`, `excluded_detection_params`, `excluded_detection_body_fields`, `enabled_detection_categories`, `detection_scan_body`, `detection_max_scan_seconds` | [`Wiring::detection_exclusions`] |
//! | `enable_penetration_detection`, `passive_mode` | [`Wiring::penetration_detection`], [`Wiring::passive_mode`] |
//! | `exclude_paths` | [`Wiring::exclusions`] (the normalized matcher) |
//! | `trusted_proxies`, `trusted_proxy_depth`, `fail_secure` | [`Wiring::client`] (the client resolution policy), `trusted_proxies` also feed [`Wiring::https`], [`Wiring::ip_ban`] and the rate-limit stage |
//! | `whitelist`, `blacklist`, `exempt_ips` | [`Wiring::ip_gate`] |
//! | `whitelist_countries`, `blocked_countries`, `geo_ip_handler`, `ipinfo_token`, `ipinfo_db_path`, `geo_ip_db_max_age`, `lazy_init` | [`Wiring::geo`], [`Wiring::geo_handler`] |
//! | `block_cloud_providers`, `cloud_ip_refresh_interval`, `cloud_ip_store` | [`Wiring::cloud`], [`Wiring::cloud_refresh`] |
//! | `enable_rate_limiting`, `rate_limit`, `rate_limit_window`, `endpoint_rate_limits`, `enable_rate_limit_auto_ban` | [`Wiring::rate_limiter`] |
//! | `enable_ip_banning`, `auto_ban_threshold`, `auto_ban_duration`, `threat_ban_config` | [`Wiring::ip_ban`] |
//! | `enable_redis`, `redis_url`, `redis_prefix`, `redis_fail_open`, `redis_max_connections` | [`Wiring::distributed`] (feature `redis`) |
//! | `enforce_https`, `trust_x_forwarded_proto` | [`Wiring::https`] |
//! | `emergency_mode`, `emergency_whitelist` | [`Wiring::emergency`] |
//! | `blocked_user_agents` | [`Wiring::user_agent`] |
//! | `custom_request_check` | [`Wiring::custom_checks`] |
//! | `auth_verifier` | [`Wiring::headers_auth`] |
//! | `custom_error_responses`, `on_block` | [`Wiring::custom_error_responses`], [`Wiring::on_block`] |
//! | `on_error`, `custom_response_modifier`, `security_headers`, `enable_cors`, `cors_*`, `global_behavior_rules`, `behavior_scan_response_body`, `behavior_max_response_body_inspect_bytes` | [`Wiring::response_processor`] (the response pass) |
//! | `log_suspicious_level`, `log_request_level`, `log_country_check_level`, `muted_check_logs`, `log_sensitive_*` | [`Wiring::request_logging`], [`Wiring::observability`] |
//! | `enable_agent`, `agent_enable_events`, `agent_enable_metrics`, `muted_event_types`, `muted_metric_types`, `enable_otel`, `otel_*`, `enable_logfire`, `logfire_service_name`, `enable_enrichment`, `agent_project_id` | [`Wiring::telemetry`], [`Wiring::events`], [`Wiring::metrics`] over the injected [`WiringOptions::agent`] |
//! | `enable_dynamic_rules`, `dynamic_rule_interval`, `dynamic_rules_cache_path`, `detection_pattern_validation_cache_path` | [`Wiring::dynamic_rules`] |
//! | `route_resolution_strict`, `body_read_timeout`, `log_format`, `custom_log_file`, `sync_body_read_max_concurrent`, `lazy_init` | [`Wiring::config`] (the adapters read these where they own the seam) |
//!
//! The remaining fields have no engine-side consumer in a Rust adapter and
//! stay on [`Wiring::config`] untouched, with the reason: the `agent_*`
//! transport knobs (`agent_api_key`, `agent_endpoint`, `agent_project_id`,
//! buffering, flush, retry, compression, signing, install id) configure the
//! injected agent itself, which the host builds from them (the agent crate
//! owns that mapping); `detection_compiler_timeout`,
//! `detection_anomaly_threshold`, `detection_slow_pattern_threshold`,
//! `detection_monitor_history_size`, `detection_max_tracked_patterns`,
//! `detection_anomaly_emission_cooldown` and
//! `detection_min_samples_for_anomaly` tune the Python performance monitor
//! (recorded as unmapped in the knob mapping); `redis_socket_*`,
//! `redis_health_check_interval` and `redis_retries` tune the Python redis
//! client; `ipinfo_*` beyond the token and path, and `sync_body_read_max_concurrent`
//! (a WSGI-only bound), do not apply.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use guard_core_engine::behavior::BehaviorTracker;
use guard_core_engine::cloud_provider::{CloudConfigError, CloudIpTable, parse_cloud_selectors};
use guard_core_engine::cors::CorsConfig;
use guard_core_engine::detect::DetectConfig;
use guard_core_engine::detection_exclusions::DetectionExclusionConfig;
use guard_core_engine::distributed::{BanStore, SlidingWindowStore};
use guard_core_engine::geo::{GeoIpHandler, parse_country_lists};
use guard_core_engine::ip_ban::{IpBanConfig, IpBanConfigError, IpBanManager};
use guard_core_engine::ip_gate::{IpGateConfig, IpGateError};
use guard_core_engine::path_matching::PathExclusions;
use guard_core_engine::rate_limit::{
    RateLimitConfig, RateLimitConfigError, RateLimitEntry, RateLimiter,
};
use guard_core_engine::security_config::{LogLevel as ConfigLogLevel, SecurityConfig};
use guard_core_engine::user_agent::UserAgentFilter;

use crate::cloud_provider::{CloudProviderStage, CloudProviderStageConfig};
use crate::composite::{CompositeAgentHandler, LogfireClient, TelemetryError, TelemetryHandler};
use crate::custom_checks::CustomChecksStage;
use crate::dynamic_rules::DynamicRuleManager;
use crate::emergency_mode::{EmergencyModeStage, EmergencyModeStageConfig};
use crate::events::{SecurityEvent, SecurityEventBus};
use crate::geo::{GeoStage, GeoStageConfig};
use crate::geo_lifecycle::{CloudRefreshScheduler, IpInfoManager};
use crate::headers_auth::HeadersAuthStage;
use crate::https_enforcement::{HttpsEnforcementStage, HttpsEnforcementStageConfig};
use crate::logging::LogLevel;
use crate::metrics::{MetricsCollector, SecurityMetric};
use crate::process_response::ResponseProcessor;
use crate::redact::SensitiveNames;
use crate::request_logging::{RequestLoggingStage, RequestLoggingStageConfig};
use crate::responses::{CustomErrorResponses, OnBlockHook};
use crate::tower::ObservabilityConfig;
use crate::user_agent::{UserAgentConfigError, UserAgentStage, UserAgentStageConfig};

/// The `unix` trusted-proxy token: authorizes `X-Forwarded-For` on a
/// peer-less (Unix socket) transport. It is not an address, so the stages
/// that parse the list never see it.
const UNIX_PROXY_TOKEN: &str = "unix";

/// The collaborators the config cannot carry.
#[derive(Clone, Default)]
pub struct WiringOptions {
    /// The telemetry agent (the reference `agent_handler`): an agent built
    /// from the `agent_*` fields, behind the facade's sink trait.
    pub agent: Option<Arc<dyn TelemetryHandler>>,
    /// The Logfire client `enable_logfire` drives.
    pub logfire_client: Option<Arc<dyn LogfireClient>>,
}

/// Why the config could not be wired: the constructor that rejected a
/// value, fail-closed.
#[derive(Debug)]
pub enum WiringError {
    /// An IP/CIDR list entry the gate cannot parse.
    IpGate(IpGateError),
    /// A zero rate-limit knob.
    RateLimit(RateLimitConfigError),
    /// A blocked user-agent pattern the `ReDoS` validator rejected.
    UserAgent(UserAgentConfigError),
    /// An invalid auto-ban knob group.
    Ban(IpBanConfigError),
    /// A `block_cloud_providers` selector the engine does not know.
    Cloud(CloudConfigError),
    /// `enable_redis` without a `redis_url`, or the backend refused it.
    Redis(String),
    /// `ipinfo_token` is required to fetch the country database.
    Geo(String),
}

impl std::fmt::Display for WiringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpGate(error) => write!(f, "ip list: {error}"),
            Self::RateLimit(error) => write!(f, "rate limit: {error}"),
            Self::UserAgent(error) => write!(f, "blocked user agent: {error}"),
            Self::Ban(error) => write!(f, "ip ban: {error}"),
            Self::Cloud(error) => write!(f, "block_cloud_providers: {error}"),
            Self::Redis(message) => write!(f, "redis: {message}"),
            Self::Geo(message) => write!(f, "geo: {message}"),
        }
    }
}

impl std::error::Error for WiringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IpGate(error) => Some(error),
            Self::RateLimit(error) => Some(error),
            Self::UserAgent(error) => Some(error),
            Self::Ban(error) => Some(error),
            Self::Cloud(error) => Some(error),
            Self::Redis(_) | Self::Geo(_) => None,
        }
    }
}

impl From<IpGateError> for WiringError {
    fn from(error: IpGateError) -> Self {
        Self::IpGate(error)
    }
}

impl From<RateLimitConfigError> for WiringError {
    fn from(error: RateLimitConfigError) -> Self {
        Self::RateLimit(error)
    }
}

impl From<UserAgentConfigError> for WiringError {
    fn from(error: UserAgentConfigError) -> Self {
        Self::UserAgent(error)
    }
}

impl From<IpBanConfigError> for WiringError {
    fn from(error: IpBanConfigError) -> Self {
        Self::Ban(error)
    }
}

impl From<CloudConfigError> for WiringError {
    fn from(error: CloudConfigError) -> Self {
        Self::Cloud(error)
    }
}

/// The client resolution policy (the reference `extract_client_ip` and
/// `handle_passthrough` knobs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPolicy {
    /// `trusted_proxies`.
    pub trusted_proxies: Vec<String>,
    /// `trusted_proxy_depth`.
    pub trusted_proxy_depth: u32,
    /// `fail_secure`: reject a peer-less request that cannot be resolved.
    pub fail_secure: bool,
}

impl ClientPolicy {
    /// Resolve one request's client: see
    /// [`guard_core_engine::ip_extraction::resolve_client`].
    #[must_use]
    pub fn resolve(
        &self,
        peer: Option<IpAddr>,
        forwarded_for: Option<&str>,
    ) -> guard_core_engine::ip_extraction::ClientResolution {
        guard_core_engine::ip_extraction::resolve_client(
            peer,
            forwarded_for,
            &self.trusted_proxies,
            self.trusted_proxy_depth,
            self.fail_secure,
        )
    }
}

/// The cloud-range refresh the pipeline drives.
///
/// The reference `CloudIpRefreshCheck`: a refresh is scheduled when more
/// than `cloud_ip_refresh_interval` seconds passed since the last one, so
/// the first request after startup schedules the first fetch.
#[derive(Clone)]
pub struct CloudRefresh {
    /// The single-flight scheduler.
    pub scheduler: Arc<CloudRefreshScheduler>,
    /// The table the refresh fills (shared with the cloud stage).
    pub table: Arc<CloudIpTable>,
    interval: Duration,
    last: Arc<Mutex<Option<std::time::Instant>>>,
}

impl CloudRefresh {
    fn new(
        scheduler: CloudRefreshScheduler,
        table: Arc<CloudIpTable>,
        interval_seconds: u64,
    ) -> Self {
        Self {
            scheduler: Arc::new(scheduler),
            table,
            interval: Duration::from_secs(interval_seconds),
            last: Arc::new(Mutex::new(None)),
        }
    }

    /// Schedule a refresh when one is due; `true` when one started.
    #[must_use]
    pub fn refresh_if_due(&self) -> bool {
        let mut last = self.last.lock().expect("cloud refresh clock");
        if last.is_some_and(|at| at.elapsed() <= self.interval) {
            return false;
        }
        let scheduled = self.scheduler.schedule_refresh(&self.table);
        if scheduled {
            *last = Some(std::time::Instant::now());
        }
        scheduled
    }

    /// Schedule a refresh now (the reference `refresh_cloud_ip_ranges`).
    #[must_use]
    pub fn refresh_now(&self) -> bool {
        self.scheduler.schedule_refresh(&self.table)
    }
}

/// The distributed (Redis) stores and knobs.
#[derive(Clone)]
pub struct Distributed {
    /// The sliding-window store.
    pub window_store: Arc<dyn SlidingWindowStore>,
    /// The ban store.
    pub ban_store: Arc<dyn BanStore>,
    /// `redis_prefix`.
    pub prefix: String,
    /// `redis_fail_open`.
    pub fail_open: bool,
}

/// The dynamic-rule driver: the manager plus the poll cadence.
#[derive(Clone)]
pub struct DynamicRules {
    /// The reference `DynamicRuleManager` over [`Wiring::live_config`].
    pub manager: Arc<DynamicRuleManager>,
    /// `dynamic_rule_interval`, seconds.
    pub interval: Duration,
}

impl DynamicRules {
    /// Start the poll loop on a std thread: hydrate the last-known rules,
    /// then one [`DynamicRuleManager::update_rules`] per interval until the
    /// returned handle is dropped. The host owns when to start it (a thread
    /// is spawned here, never at wiring time).
    #[must_use]
    pub fn spawn(&self) -> DynamicRulesHandle {
        let halt = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&halt);
        let manager = Arc::clone(&self.manager);
        let interval = self.interval;
        std::thread::spawn(move || {
            let _ = manager.hydrate_last_known_rules();
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = manager.update_rules();
                let mut remaining = interval;
                while !remaining.is_zero() && !flag.load(std::sync::atomic::Ordering::Relaxed) {
                    let nap = Duration::from_millis(100).min(remaining);
                    std::thread::sleep(nap);
                    remaining = remaining.saturating_sub(nap);
                }
            }
        });
        DynamicRulesHandle { stop: halt }
    }
}

/// Stops the dynamic-rule poll loop when dropped.
pub struct DynamicRulesHandle {
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for DynamicRulesHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Everything a `SecurityConfig` describes, built once.
///
/// See the module docs for the field-to-part table.
#[allow(clippy::struct_excessive_bools)]
pub struct Wiring {
    /// The config the parts were built from (the live handle's initial
    /// value; fields no part consumes are read from here).
    pub config: SecurityConfig,
    /// The engine detect knobs.
    pub detect: DetectConfig,
    /// The global detection exclusions (always present: the scan reads the
    /// resolved categories, the body toggle and the scan budget).
    pub detection_exclusions: DetectionExclusionConfig,
    /// `passive_mode`.
    pub passive_mode: bool,
    /// `enable_penetration_detection`.
    pub penetration_detection: bool,
    /// The normalized `exclude_paths` matcher.
    pub exclusions: PathExclusions,
    /// The client resolution policy.
    pub client: ClientPolicy,
    /// The global IP gate, when any list is configured.
    pub ip_gate: Option<IpGateConfig>,
    /// The rate limiter, when `enable_rate_limiting`.
    pub rate_limiter: Option<RateLimiter>,
    /// The ban manager and its knobs, when `enable_ip_banning`.
    pub ip_ban: Option<(IpBanManager, IpBanConfig)>,
    /// The distributed stores, when `enable_redis` and the crate's `redis`
    /// feature is on.
    pub distributed: Option<Distributed>,
    /// `enable_redis` is set but this build has no Redis backend (the
    /// `redis` feature is off): rate limits and bans stay per process. The
    /// reference default is `enable_redis = true`, so the default config
    /// lands here in a build without the feature.
    pub redis_backend_missing: bool,
    /// The HTTPS-enforcement stage (always built: the route arm needs it).
    pub https: HttpsEnforcementStage,
    /// The emergency stage, when `emergency_mode` or a whitelist is set.
    pub emergency: Option<EmergencyModeStage>,
    /// The blocked-user-agent stage.
    pub user_agent: Option<UserAgentStage>,
    /// The geo country stage, when country rules are configured.
    pub geo: Option<GeoStage>,
    /// The geolocation handler the stages resolve countries through.
    pub geo_handler: Option<Arc<dyn GeoIpHandler>>,
    /// The cloud-provider stage, when providers are blocked.
    pub cloud: Option<CloudProviderStage>,
    /// The cloud range refresh seam, with the stage.
    pub cloud_refresh: Option<CloudRefresh>,
    /// The global `auth_verifier` stage.
    pub headers_auth: Option<HeadersAuthStage>,
    /// The global `custom_request_check` stage.
    pub custom_checks: Option<CustomChecksStage>,
    /// The request-logging stage (only with `log_request_level`).
    pub request_logging: Option<RequestLoggingStage>,
    /// The log and redaction knobs.
    pub observability: Option<ObservabilityConfig>,
    /// `custom_error_responses`.
    pub custom_error_responses: CustomErrorResponses,
    /// `on_block`.
    pub on_block: Option<OnBlockHook>,
    /// The response pass: built whenever it has something to do (headers,
    /// CORS, behavior rules or the modifier). The metrics collector is the
    /// adapter's to drive, because the adapter times the request.
    pub response_processor: Option<ResponseProcessor>,
    /// The telemetry fan-out over the injected agent and the otel/logfire
    /// sinks; `None` without any sink.
    pub telemetry: Option<Arc<CompositeAgentHandler>>,
    /// The event bus over the telemetry fan-out.
    pub events: Option<Arc<SecurityEventBus>>,
    /// The metrics collector over the telemetry fan-out.
    pub metrics: Option<MetricsCollector>,
    /// The dynamic-rule driver, when `enable_dynamic_rules` and a sink
    /// exist.
    pub dynamic_rules: Option<DynamicRules>,
    /// The live config handle the dynamic-rule manager mutates.
    pub live_config: Arc<RwLock<SecurityConfig>>,
}

impl std::fmt::Debug for Wiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wiring")
            .field("passive_mode", &self.passive_mode)
            .field("client", &self.client)
            .field("rate_limiter", &self.rate_limiter.is_some())
            .field("ip_ban", &self.ip_ban.is_some())
            .finish_non_exhaustive()
    }
}

const fn map_log_level(level: ConfigLogLevel) -> LogLevel {
    match level {
        ConfigLogLevel::Info => LogLevel::Info,
        ConfigLogLevel::Debug => LogLevel::Debug,
        ConfigLogLevel::Warning => LogLevel::Warning,
        ConfigLogLevel::Error => LogLevel::Error,
        ConfigLogLevel::Critical => LogLevel::Critical,
    }
}

/// The proxies the address-parsing stages accept: the `unix` token is not
/// an address.
fn address_proxies(config: &SecurityConfig) -> Vec<String> {
    config
        .trusted_proxies
        .iter()
        .filter(|entry| entry.as_str() != UNIX_PROXY_TOKEN)
        .cloned()
        .collect()
}

fn sensitive(config: &SecurityConfig) -> SensitiveNames {
    SensitiveNames::new(
        Some(&config.log_sensitive_headers.iter().cloned().collect()),
        Some(&config.log_sensitive_params.iter().cloned().collect()),
        Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
    )
}

fn muted_check_logs(config: &SecurityConfig) -> std::collections::HashSet<String> {
    config.muted_check_logs.iter().cloned().collect()
}

/// A `GeoIpHandler` over the `GeoIP` database lifecycle.
struct IpInfoHandler(Arc<IpInfoManager>);

impl GeoIpHandler for IpInfoHandler {
    fn get_country(&self, ip: IpAddr) -> Option<String> {
        self.0.get_country(ip)
    }
}

/// The composite fan-out behind the sink trait the dynamic-rule manager
/// takes (its `get_dynamic_rules` answers the first non-empty rule set).
struct CompositeSink(Arc<CompositeAgentHandler>);

impl TelemetryHandler for CompositeSink {
    fn handler_name(&self) -> &'static str {
        "CompositeAgentHandler"
    }

    fn start(&self) -> Result<(), TelemetryError> {
        self.0.start();
        Ok(())
    }

    fn stop(&self) -> Result<(), TelemetryError> {
        self.0.stop();
        Ok(())
    }

    fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
        self.0.send_event(event);
        Ok(())
    }

    fn send_metric(&self, metric: &SecurityMetric) -> Result<(), TelemetryError> {
        self.0.send_metric(metric);
        Ok(())
    }

    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        Ok(self.0.get_dynamic_rules().0)
    }

    fn health_check(&self) -> bool {
        self.0.health_check()
    }
}

impl Wiring {
    /// Wire `config` with no injected collaborators.
    ///
    /// # Errors
    ///
    /// [`WiringError`] naming the value an engine constructor rejected.
    pub fn from_security_config(config: &SecurityConfig) -> Result<Self, WiringError> {
        Self::from_security_config_with(config, &WiringOptions::default())
    }

    /// Wire `config` with the injected `options` (the telemetry agent and
    /// the Logfire client).
    ///
    /// # Errors
    ///
    /// [`WiringError`] naming the value an engine constructor rejected.
    #[allow(clippy::too_many_lines)]
    pub fn from_security_config_with(
        config: &SecurityConfig,
        options: &WiringOptions,
    ) -> Result<Self, WiringError> {
        let detect = DetectConfig {
            max_content_length: config.detection_max_content_length,
            max_full_scan_bytes: config.detection_max_body_inspect_bytes,
            preserve_attack_patterns: config.detection_preserve_attack_patterns,
            semantic_threshold: config.detection_semantic_threshold,
            threat_score_threshold: config.detection_threat_score_threshold,
            binary_min_run_length: config.detection_binary_min_run_length,
            max_scan_values: config.detection_max_scan_values,
            max_scan_chars: config.detection_max_scan_chars,
            max_json_depth: config.detection_max_json_depth,
        };
        let detection_exclusions = DetectionExclusionConfig {
            excluded_detection_headers: config.excluded_detection_headers.iter().cloned().collect(),
            excluded_semantic_detection_headers: config
                .excluded_semantic_detection_headers
                .iter()
                .cloned()
                .collect(),
            excluded_detection_params: config.excluded_detection_params.iter().cloned().collect(),
            excluded_detection_body_fields: config
                .excluded_detection_body_fields
                .iter()
                .cloned()
                .collect(),
            enabled_detection_categories: (!config.enabled_detection_categories.is_empty()).then(
                || {
                    config
                        .enabled_detection_categories
                        .iter()
                        .cloned()
                        .collect()
                },
            ),
            detection_scan_body: Some(config.detection_scan_body),
            max_scan_seconds: Some(config.detection_max_scan_seconds),
        };

        let ip_gate = if config.whitelist.is_some()
            || !config.blacklist.is_empty()
            || !config.exempt_ips.is_empty()
        {
            Some(IpGateConfig::new(
                config.whitelist.clone().unwrap_or_default(),
                config.blacklist.iter().cloned(),
                config.exempt_ips.iter().cloned(),
            )?)
        } else {
            None
        };

        let rate_limiter = if config.enable_rate_limiting {
            let mut endpoint_rate_limits = std::collections::HashMap::new();
            for (path, (requests, window)) in &config.endpoint_rate_limits {
                endpoint_rate_limits.insert(
                    path.clone(),
                    RateLimitEntry::new(*requests, *window).map_err(|error| {
                        RateLimitConfigError {
                            field: std::borrow::Cow::Owned(format!(
                                "endpoint_rate_limits[{path}].{}",
                                error.field
                            )),
                            reason: error.reason,
                        }
                    })?,
                );
            }
            Some(RateLimiter::new(RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: config.rate_limit,
                rate_limit_window: config.rate_limit_window,
                enable_rate_limit_auto_ban: config.enable_rate_limit_auto_ban,
                endpoint_rate_limits,
            })?)
        } else {
            None
        };

        let ip_ban = if config.enable_ip_banning {
            Some((
                IpBanManager::with_trusted_proxies(address_proxies(config))?,
                config.ip_ban_config(),
            ))
        } else {
            None
        };

        let distributed = Self::build_distributed(config)?;
        let (geo_handler, geo) = Self::build_geo(config, None)?;
        let (cloud, cloud_refresh) = Self::build_cloud(config)?;

        let https = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig {
            enforce_https: config.enforce_https,
            trust_x_forwarded_proto: config.trust_x_forwarded_proto,
            passive_mode: config.passive_mode,
        })
        .trusted_proxies(address_proxies(config))
        .build()?;

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

        let user_agent = if config.blocked_user_agents.is_empty() {
            None
        } else {
            Some(
                UserAgentStage::builder(UserAgentStageConfig {
                    blocked_user_agents: UserAgentFilter::new(
                        config.blocked_user_agents.iter().cloned(),
                    )?,
                    ip_ban: config.ip_ban_config(),
                    passive_mode: config.passive_mode,
                })
                .build()?,
            )
        };

        let (telemetry, events, metrics) = Self::build_telemetry(config, options);

        let custom_checks = config.custom_request_check.as_ref().map(|check| {
            let mut builder = CustomChecksStage::builder()
                .custom_request("custom_request_check", Arc::clone(check))
                .passive_mode(config.passive_mode);
            if let Some(bus) = &events {
                builder = builder.events(Arc::clone(bus));
            }
            builder.build()
        });

        let headers_auth = config.auth_verifier.as_ref().map(|verifier| {
            HeadersAuthStage::new(Some(Arc::clone(verifier)), Arc::new(|_path| None))
        });

        let request_logging = config.log_request_level.map(|level| {
            RequestLoggingStage::new(RequestLoggingStageConfig {
                log_request_level: Some(map_log_level(level)),
                muted_check_logs: Some(muted_check_logs(config)),
                sensitive: sensitive(config),
            })
        });
        let observability = (config.log_suspicious_level.is_some()
            || config.log_country_check_level.is_some())
        .then(|| ObservabilityConfig {
            log_suspicious_level: config.log_suspicious_level.map(map_log_level),
            log_request_level: config.log_request_level.map(map_log_level),
            log_country_check_level: config.log_country_check_level.map(map_log_level),
            muted_check_logs: Some(muted_check_logs(config)),
            sensitive: sensitive(config),
        });

        let response_processor = Self::build_response_processor(config, ip_ban.as_ref());

        let live_config = Arc::new(RwLock::new(config.clone()));
        let dynamic_rules = Self::build_dynamic_rules(
            config,
            telemetry.as_ref(),
            ip_ban.as_ref().map(|(manager, _)| manager),
            &live_config,
        );

        Ok(Self {
            config: config.clone(),
            detect,
            detection_exclusions,
            passive_mode: config.passive_mode,
            penetration_detection: config.enable_penetration_detection,
            exclusions: PathExclusions::new(&config.exclude_paths),
            client: ClientPolicy {
                trusted_proxies: config.trusted_proxies.clone(),
                trusted_proxy_depth: config.trusted_proxy_depth,
                fail_secure: config.fail_secure,
            },
            ip_gate,
            rate_limiter,
            ip_ban,
            distributed,
            redis_backend_missing: config.enable_redis && !cfg!(feature = "redis"),
            https,
            emergency,
            user_agent,
            geo,
            geo_handler,
            cloud,
            cloud_refresh,
            headers_auth,
            custom_checks,
            request_logging,
            observability,
            custom_error_responses: config
                .custom_error_responses
                .iter()
                .map(|(status, body)| (*status, body.clone()))
                .collect(),
            on_block: config.on_block.clone(),
            response_processor,
            telemetry,
            events,
            metrics,
            dynamic_rules,
            live_config,
        })
    }

    #[cfg(feature = "redis")]
    fn build_distributed(config: &SecurityConfig) -> Result<Option<Distributed>, WiringError> {
        if !config.enable_redis {
            return Ok(None);
        }
        let url = config
            .redis_url
            .as_deref()
            .ok_or_else(|| WiringError::Redis(String::from("enable_redis needs redis_url")))?;
        let mut store = crate::redis_store::RedisStore::connect(url)
            .map_err(|error| WiringError::Redis(error.to_string()))?;
        if let Some(max) = config.redis_max_connections {
            store = store.with_max_connections(usize::try_from(max).unwrap_or(usize::MAX));
        }
        let store = Arc::new(store);
        Ok(Some(Distributed {
            window_store: Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
            ban_store: store as Arc<dyn BanStore>,
            prefix: config.redis_prefix.clone(),
            fail_open: config.redis_fail_open,
        }))
    }

    #[cfg(not(feature = "redis"))]
    #[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)] // same signature as the redis arm
    fn build_distributed(_config: &SecurityConfig) -> Result<Option<Distributed>, WiringError> {
        Ok(None)
    }

    #[allow(clippy::type_complexity)]
    fn build_geo(
        config: &SecurityConfig,
        database_url: Option<&str>,
    ) -> Result<(Option<Arc<dyn GeoIpHandler>>, Option<GeoStage>), WiringError> {
        let gate = parse_country_lists(&config.whitelist_countries, &config.blocked_countries);
        let handler: Option<Arc<dyn GeoIpHandler>> = if let Some(handler) = &config.geo_ip_handler {
            Some(Arc::clone(handler))
        } else if gate.has_rules() || config.ipinfo_token.is_some() {
            if config.ipinfo_token.is_none() {
                return Err(WiringError::Geo(String::from(
                    "country rules need geo_ip_handler or ipinfo_token",
                )));
            }
            let mut manager = IpInfoManager::from_config(config)
                .map_err(|error| WiringError::Geo(error.to_string()))?;
            if let Some(url) = database_url {
                manager = manager.with_database_url(url.to_owned());
            }
            let manager = Arc::new(manager);
            if config.lazy_init {
                let background = Arc::clone(&manager);
                std::thread::spawn(move || {
                    let _ = background.initialize();
                });
            } else {
                let _ = manager.initialize();
            }
            Some(Arc::new(IpInfoHandler(manager)))
        } else {
            None
        };
        let stage = gate.has_rules().then(|| {
            GeoStage::new(GeoStageConfig {
                gate,
                handler: handler.clone(),
                passive_mode: config.passive_mode,
            })
        });
        Ok((handler, stage))
    }

    #[allow(clippy::type_complexity)]
    fn build_cloud(
        config: &SecurityConfig,
    ) -> Result<(Option<CloudProviderStage>, Option<CloudRefresh>), WiringError> {
        let Some(providers) = config
            .block_cloud_providers
            .as_ref()
            .filter(|providers| !providers.is_empty())
        else {
            return Ok((None, None));
        };
        let selectors = parse_cloud_selectors(providers)?;
        let table = Arc::new(CloudIpTable::default());
        let stage = CloudProviderStage::new(CloudProviderStageConfig {
            block_cloud_providers: selectors,
            table: (*table).clone(),
            passive_mode: config.passive_mode,
        });
        let refresh = CloudRefresh::new(
            CloudRefreshScheduler::new(),
            table,
            config.cloud_ip_refresh_interval,
        );
        Ok((Some(stage), Some(refresh)))
    }

    #[allow(clippy::type_complexity)]
    fn build_telemetry(
        config: &SecurityConfig,
        options: &WiringOptions,
    ) -> (
        Option<Arc<CompositeAgentHandler>>,
        Option<Arc<SecurityEventBus>>,
        Option<MetricsCollector>,
    ) {
        let has_sink = options.agent.is_some()
            || config.enable_otel
            || (config.enable_logfire && options.logfire_client.is_some());
        if !has_sink {
            return (None, None, None);
        }
        let composite = Arc::new(crate::composite::build_composite_handler(
            config,
            options.agent.clone(),
            options.logfire_client.clone(),
        ));
        let mut bus = SecurityEventBus::new(config.agent_enable_events)
            .with_filter(crate::composite::build_event_filter(config))
            .on_event(composite.event_handler());
        if config.enable_enrichment {
            bus = bus.with_enricher(crate::enrichment::EventEnricher::new(
                crate::composite::enrichment_identity(config),
            ));
        }
        let metrics = MetricsCollector::new(config.agent_enable_metrics)
            .with_filter(crate::composite::build_metric_filter(config))
            .with_handler(composite.metric_handler());
        (Some(composite), Some(Arc::new(bus)), Some(metrics))
    }

    fn build_response_processor(
        config: &SecurityConfig,
        ip_ban: Option<&(IpBanManager, IpBanConfig)>,
    ) -> Option<ResponseProcessor> {
        let wants_headers = config.security_headers.enabled;
        if !(wants_headers
            || config.enable_cors
            || !config.global_behavior_rules.is_empty()
            || config.custom_response_modifier.is_some())
        {
            return None;
        }
        let cors = config.enable_cors.then(|| CorsConfig {
            enabled: true,
            allow_origins: config.cors_allow_origins.clone(),
            allow_methods: config.cors_allow_methods.clone(),
            allow_headers: config.cors_allow_headers.clone(),
            allow_credentials: config.cors_allow_credentials,
            expose_headers: config.cors_expose_headers.clone(),
            max_age: config.cors_max_age,
        });
        let mut processor = ResponseProcessor::new(
            wants_headers.then(|| config.security_headers.clone()),
            cors,
            config.global_behavior_rules.clone(),
            Arc::new(Mutex::new(BehaviorTracker::new())),
            ip_ban.map_or_else(IpBanManager::new, |(manager, _)| manager.clone()),
            config.behavior_scan_response_body,
            config.behavior_max_response_body_inspect_bytes,
            config.passive_mode,
        );
        if let Some(modifier) = &config.custom_response_modifier {
            processor = processor.with_response_modifier(Arc::clone(modifier));
        }
        if let Some(hook) = &config.on_error {
            let hook = Arc::clone(hook);
            processor = processor.with_on_error(Arc::new(move |stage, error, context| {
                let context = context.iter().cloned().collect();
                hook(stage, error, &context);
            }));
        }
        Some(processor)
    }

    fn build_dynamic_rules(
        config: &SecurityConfig,
        telemetry: Option<&Arc<CompositeAgentHandler>>,
        bans: Option<&IpBanManager>,
        live_config: &Arc<RwLock<SecurityConfig>>,
    ) -> Option<DynamicRules> {
        if !config.enable_dynamic_rules {
            return None;
        }
        let telemetry = telemetry?;
        let mut manager = DynamicRuleManager::new(Arc::clone(live_config))
            .with_sink(Arc::new(CompositeSink(Arc::clone(telemetry))));
        if let Some(bans) = bans {
            manager = manager.with_bans(bans.clone());
        }
        if let Some(path) = config.detection_pattern_validation_cache_path.as_deref() {
            manager = manager.with_validation_cache_path(std::path::Path::new(path));
        }
        Some(DynamicRules {
            manager: Arc::new(manager),
            interval: Duration::from_secs(config.dynamic_rule_interval),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use guard_core_engine::payload::ResponseBits;

    use super::*;

    fn config() -> SecurityConfig {
        SecurityConfig::default()
    }

    struct Fixed;

    impl GeoIpHandler for Fixed {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some("US".to_owned())
        }
    }

    struct Client;
    impl crate::composite::LogfireClient for Client {
        fn is_configured(&self) -> bool {
            false
        }

        fn configure(&self, _service_name: &str) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn span(
            &self,
            _name: &str,
            _attributes: &std::collections::BTreeMap<String, serde_json::Value>,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn info(
            &self,
            _message: &str,
            _attributes: &std::collections::BTreeMap<String, serde_json::Value>,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn shutdown(&self) -> Result<(), TelemetryError> {
            Ok(())
        }
    }

    fn wire(config: &SecurityConfig) -> Wiring {
        Wiring::from_security_config(config).expect("wired")
    }

    fn wire_err(config: &SecurityConfig) -> WiringError {
        Wiring::from_security_config(config).expect_err("rejected")
    }

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// A sink that counts its dynamic-rule polls and records what it saw.
    #[derive(Default)]
    struct CountingSink {
        polls: AtomicUsize,
        events: AtomicUsize,
        metrics: AtomicUsize,
    }

    impl TelemetryHandler for CountingSink {
        fn handler_name(&self) -> &'static str {
            "CountingSink"
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
            self.events.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
            self.metrics.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn health_check(&self) -> bool {
            true
        }
    }

    fn with_agent(config: &SecurityConfig) -> (Wiring, Arc<CountingSink>) {
        let sink = Arc::new(CountingSink::default());
        let wiring = Wiring::from_security_config_with(
            config,
            &WiringOptions {
                agent: Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
                logfire_client: None,
            },
        )
        .expect("wired");
        (wiring, sink)
    }

    #[test]
    fn the_defaults_wire_the_always_on_parts() {
        let wiring = wire(&config());
        assert_eq!(wiring.detect.max_content_length, 10_000);
        assert!(wiring.penetration_detection);
        assert!(!wiring.passive_mode);
        assert!(wiring.exclusions.is_excluded("/static/app.js"));
        assert!(!wiring.exclusions.is_excluded("/staticx"));
        assert_eq!(
            wiring.client,
            ClientPolicy {
                trusted_proxies: Vec::new(),
                trusted_proxy_depth: 1,
                fail_secure: true,
            }
        );
        assert!(wiring.ip_gate.is_none());
        assert!(wiring.geo.is_none() && wiring.geo_handler.is_none());
        assert!(wiring.cloud.is_none() && wiring.cloud_refresh.is_none());
        assert_eq!(wiring.distributed.is_some(), cfg!(feature = "redis"));
        assert!(wiring.telemetry.is_none() && wiring.events.is_none() && wiring.metrics.is_none());
        assert!(wiring.dynamic_rules.is_none());
        assert!(wiring.custom_checks.is_none() && wiring.headers_auth.is_none());
        assert!(wiring.user_agent.is_none() && wiring.emergency.is_none());
        assert!(wiring.request_logging.is_none());
        // The reference default `log_suspicious_level` is WARNING.
        assert!(wiring.observability.is_some());
        assert!(wiring.on_block.is_none());
        assert!(wiring.custom_error_responses.is_empty());
        assert_eq!(wiring.detection_exclusions.detection_scan_body, Some(true));
        assert!(format!("{wiring:?}").contains("Wiring"));
        assert!(wiring.config.fail_secure);
    }

    #[test]
    fn the_client_policy_resolves_like_the_reference() {
        let mut config = config();
        config.trusted_proxies = vec!["10.0.0.0/8".to_owned()];
        let wiring = wire(&config);
        let resolution = wiring
            .client
            .resolve(Some("10.0.0.1".parse().unwrap()), Some("203.0.113.7"));
        assert_eq!(resolution.ip, Some("203.0.113.7".parse().unwrap()));
        assert!(wiring.client.resolve(None, None).reject);
    }

    #[test]
    fn ip_lists_build_the_gate_and_fail_closed() {
        let mut config = config();
        config.blacklist = vec!["203.0.113.9".to_owned()];
        assert!(wire(&config).ip_gate.is_some());
        config.blacklist = vec!["not-an-ip".to_owned()];
        assert!(matches!(wire_err(&config), WiringError::IpGate(_)));
    }

    #[test]
    fn rate_limits_carry_the_endpoint_tiers_and_fail_closed() {
        let mut config = config();
        config.enable_rate_limiting = true;
        config
            .endpoint_rate_limits
            .insert("/login".to_owned(), (5, 60));
        config.enable_rate_limit_auto_ban = true;
        let wiring = wire(&config);
        let limiter = wiring.rate_limiter.expect("limiter");
        assert!(limiter.config().enable_rate_limit_auto_ban);
        assert_eq!(
            limiter.config().endpoint_rate_limits.get("/login"),
            Some(&RateLimitEntry {
                requests: 5,
                window: 60
            })
        );

        config
            .endpoint_rate_limits
            .insert("/zero".to_owned(), (0, 60));
        assert!(matches!(
            wire_err(&config),
            WiringError::RateLimit(error) if error.field.contains("endpoint_rate_limits[/zero]")
        ));
        config.endpoint_rate_limits.clear();
        config.rate_limit = 0;
        assert!(matches!(wire_err(&config), WiringError::RateLimit(_)));

        config.enable_rate_limiting = false;
        assert!(wire(&config).rate_limiter.is_none());
    }

    #[test]
    fn bans_skip_the_unix_token_and_reject_bad_proxies() {
        let mut config = config();
        config.enable_ip_banning = true;
        config.trusted_proxies = vec!["unix".to_owned(), "10.0.0.0/8".to_owned()];
        let wiring = wire(&config);
        let (manager, ban_config) = wiring.ip_ban.expect("ban manager");
        assert!(ban_config.enable_ip_banning);
        assert_eq!(
            manager.ban_ip("10.1.2.3".parse().unwrap(), 60, "test"),
            Ok(false),
            "a trusted proxy is never banned"
        );
        assert_eq!(
            manager.ban_ip("203.0.113.9".parse().unwrap(), 60, "test"),
            Ok(true)
        );
        config.trusted_proxies = vec!["also-bad".to_owned()];
        assert!(matches!(wire_err(&config), WiringError::IpGate(_)));
        config.trusted_proxies.clear();
        config.enable_ip_banning = false;
        assert!(wire(&config).ip_ban.is_none());
    }

    #[cfg(feature = "redis")]
    #[test]
    fn redis_builds_the_distributed_stores_from_the_url() {
        let mut config = config();
        config.enable_redis = true;
        config.redis_url = Some("redis://127.0.0.1:1".to_owned());
        config.redis_prefix = "tenant:".to_owned();
        config.redis_fail_open = true;
        config.redis_max_connections = Some(4);
        let distributed = wire(&config).distributed.expect("stores");
        assert_eq!(distributed.prefix, "tenant:");
        assert!(distributed.fail_open);

        config.redis_url = None;
        assert!(matches!(wire_err(&config), WiringError::Redis(_)));
        config.redis_url = Some("not a url".to_owned());
        assert!(matches!(wire_err(&config), WiringError::Redis(_)));
        config.enable_redis = false;
        assert!(wire(&config).distributed.is_none());
    }

    #[cfg(not(feature = "redis"))]
    #[test]
    fn redis_without_its_feature_is_reported_not_silent() {
        let mut config = config();
        config.enable_redis = true;
        let wiring = wire(&config);
        assert!(wiring.redis_backend_missing);
        assert!(wiring.distributed.is_none());
        config.enable_redis = false;
        assert!(!wire(&config).redis_backend_missing);
    }

    #[test]
    fn country_rules_need_a_handler_or_a_token() {
        let mut config = config();
        config.whitelist_countries = set(&["US"]);
        assert!(matches!(
            wire_err(&config),
            WiringError::Geo(message) if message.contains("ipinfo_token")
        ));

        config.geo_ip_handler = Some(Arc::new(Fixed));
        let wiring = wire(&config);
        assert!(wiring.geo.is_some());
        let handler = wiring.geo_handler.as_ref().expect("handler");
        assert_eq!(
            handler
                .get_country("203.0.113.9".parse().unwrap())
                .as_deref(),
            Some("US")
        );

        // A handler with no country rules builds the handler, no stage.
        config.whitelist_countries.clear();
        let wiring = wire(&config);
        assert!(wiring.geo.is_none() && wiring.geo_handler.is_some());
    }

    #[test]
    fn the_ipinfo_token_builds_the_database_handler_without_touching_the_network() {
        let dir = std::env::temp_dir().join(format!("guard-core-wiring-{}", std::process::id()));
        let mut config = config();
        config.blocked_countries = set(&["CN"]);
        config.ipinfo_token = Some("token".to_owned());
        config.ipinfo_db_path = Some(dir.join("country_asn.mmdb"));

        // lazy_init: the load runs on a background thread (the unroutable
        // endpoint fails it), the stage and handler exist immediately.
        config.lazy_init = true;
        let (handler, stage) =
            Wiring::build_geo(&config, Some("http://127.0.0.1:1/db")).expect("geo");
        let handler = handler.expect("handler");
        assert!(stage.is_some());
        assert_eq!(handler.get_country("203.0.113.9".parse().unwrap()), None);

        // Eager: the load runs before the wiring returns.
        config.lazy_init = false;
        let (handler, _stage) = Wiring::build_geo(&config, None).expect("geo");
        assert!(handler.is_some());
        let _ = std::fs::remove_dir_all(&dir);

        // A token without country rules still builds the handler.
        config.blocked_countries.clear();
        config.lazy_init = true;
        let (handler, stage) =
            Wiring::build_geo(&config, Some("http://127.0.0.1:1/db")).expect("geo");
        assert!(handler.is_some() && stage.is_none());
    }

    #[test]
    fn cloud_providers_build_the_stage_and_the_refresh_seam() {
        let mut config = config();
        config.block_cloud_providers = Some(set(&["AWS", "GCP"]));
        config.cloud_ip_refresh_interval = 3600;
        let wiring = wire(&config);
        assert!(wiring.cloud.is_some());
        assert!(wiring.cloud_refresh.is_some());

        config.block_cloud_providers = Some(set(&["Nope"]));
        assert!(matches!(wire_err(&config), WiringError::Cloud(_)));
        config.block_cloud_providers = Some(BTreeSet::new());
        assert!(wire(&config).cloud.is_none());
        config.block_cloud_providers = None;
        assert!(wire(&config).cloud.is_none());
    }

    #[test]
    fn the_refresh_runs_when_due_and_waits_out_the_interval() {
        let table = Arc::new(CloudIpTable::default());
        let scheduler = CloudRefreshScheduler::new()
            .with_providers(vec!["AWS"])
            .with_provider_endpoint("AWS", String::from("http://127.0.0.1:1/aws"));
        let refresh = CloudRefresh::new(scheduler, table, 3600);
        assert!(refresh.refresh_if_due(), "the first request schedules");
        // Wait for the single-flight gate to clear, then the interval holds.
        let settled = (0..500).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            !refresh.scheduler.refresh_in_flight()
        });
        assert!(settled);
        assert!(!refresh.refresh_if_due(), "inside the interval");
        assert!(refresh.refresh_now(), "an explicit refresh always runs");
        let settled = (0..500).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            !refresh.scheduler.refresh_in_flight()
        });
        assert!(settled);
    }

    #[test]
    fn a_refresh_in_flight_is_not_marked_as_scheduled_twice() {
        let table = Arc::new(CloudIpTable::default());
        let scheduler = CloudRefreshScheduler::new()
            .with_providers(vec!["AWS"])
            .with_provider_endpoint("AWS", String::from("http://127.0.0.1:1/aws"));
        let refresh = CloudRefresh::new(scheduler, table, 0);
        assert!(refresh.refresh_now());
        // The interval is zero (always due) but the single-flight gate
        // refuses a second schedule while one runs.
        let second = refresh.refresh_if_due();
        let settled = (0..500).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            !refresh.scheduler.refresh_in_flight()
        });
        assert!(settled);
        // Whether the first finished before the second call is a race;
        // either answer leaves the gate consistent.
        let _ = second;
    }

    #[test]
    fn the_https_stage_trusts_the_forwarded_proto_through_the_proxy_list() {
        let mut config = config();
        config.enforce_https = true;
        config.trust_x_forwarded_proto = true;
        config.trusted_proxies = vec!["unix".to_owned(), "10.0.0.0/8".to_owned()];
        let wiring = wire(&config);
        // A trusted peer's `X-Forwarded-Proto: https` passes; an untrusted
        // peer's claim does not (the redirect answers).
        assert!(
            wiring
                .https
                .decide("/", "http", Some("10.0.0.1"), Some("https"), "https://x/")
                .is_none()
        );
        assert!(
            wiring
                .https
                .decide("/", "http", Some("192.0.2.9"), Some("https"), "https://x/")
                .is_some()
        );
    }

    #[test]
    fn the_optional_stages_build_from_their_knobs() {
        let mut config = config();
        config.emergency_mode = true;
        config.blocked_user_agents = vec!["badbot".to_owned()];
        config.custom_error_responses.insert(403, "no".to_owned());
        config.on_block = Some(Arc::new(|_payload| {}));
        config.custom_request_check = Some(Arc::new(|_context| None));
        config.auth_verifier = Some(Arc::new(|_credential| false));
        // With a bus installed the custom check emits through it.
        config.agent_enable_events = true;
        let (wiring, _sink) = with_agent(&config);
        assert!(wiring.custom_checks.is_some());
        let wiring = wire(&config);
        assert!(wiring.emergency.is_some());
        assert!(wiring.user_agent.is_some());
        assert_eq!(
            wiring.custom_error_responses.get(&403).map(String::as_str),
            Some("no")
        );
        assert!(wiring.on_block.is_some());
        assert!(wiring.custom_checks.is_some());
        assert!(wiring.headers_auth.is_some());

        config.blocked_user_agents = vec!["(a+)+$".to_owned()];
        assert!(matches!(wire_err(&config), WiringError::UserAgent(_)));
        config.blocked_user_agents.clear();
        config.emergency_mode = false;
        config.emergency_whitelist = vec!["203.0.113.9".to_owned()];
        assert!(wire(&config).emergency.is_some());
        config.emergency_whitelist = vec!["junk".to_owned()];
        assert!(matches!(wire_err(&config), WiringError::IpGate(_)));
    }

    #[test]
    fn the_log_levels_build_the_request_and_observability_knobs() {
        let mut config = config();
        config.log_request_level = Some(ConfigLogLevel::Info);
        config.log_suspicious_level = None;
        config.log_country_check_level = None;
        let wiring = wire(&config);
        assert!(wiring.request_logging.is_some());
        assert!(wiring.observability.is_none());

        config.log_suspicious_level = Some(ConfigLogLevel::Warning);
        let observability = wire(&config).observability.expect("observability");
        assert_eq!(observability.log_suspicious_level, Some(LogLevel::Warning));
        assert_eq!(observability.log_request_level, Some(LogLevel::Info));

        config.log_suspicious_level = None;
        config.log_country_check_level = Some(ConfigLogLevel::Debug);
        let observability = wire(&config).observability.expect("observability");
        assert_eq!(observability.log_suspicious_level, None);
        assert_eq!(observability.log_country_check_level, Some(LogLevel::Debug));

        for (level, expected) in [
            (ConfigLogLevel::Info, LogLevel::Info),
            (ConfigLogLevel::Debug, LogLevel::Debug),
            (ConfigLogLevel::Warning, LogLevel::Warning),
            (ConfigLogLevel::Error, LogLevel::Error),
            (ConfigLogLevel::Critical, LogLevel::Critical),
        ] {
            assert_eq!(map_log_level(level), expected);
        }
    }

    fn bare_response() -> ResponseBits {
        ResponseBits {
            status: 200,
            body: None,
            headers: std::collections::BTreeMap::new(),
        }
    }

    fn view() -> guard_core_engine::payload::RequestBits {
        guard_core_engine::payload::RequestBits {
            method: "GET".to_owned(),
            url_path: "/x".to_owned(),
            client_ip: "192.0.2.1".to_owned(),
            origin: Some("https://app.example.com".to_owned()),
        }
    }

    #[test]
    fn the_response_pass_is_built_only_when_it_has_work() {
        let mut config = config();
        config.security_headers.enabled = false;
        assert!(wire(&config).response_processor.is_none());

        config.security_headers.enabled = true;
        assert!(wire(&config).response_processor.is_some());

        // CORS lands with the exposed headers.
        config.security_headers.enabled = false;
        config.enable_cors = true;
        config.cors_allow_origins = vec!["https://app.example.com".to_owned()];
        config.cors_expose_headers = vec!["X-Request-Id".to_owned()];
        let processor = wire(&config).response_processor.expect("processor");
        let mut response = bare_response();
        processor.process(&view(), &mut response, None, std::time::SystemTime::now());
        assert_eq!(
            response
                .headers
                .get("Access-Control-Expose-Headers")
                .map(String::as_str),
            Some("X-Request-Id")
        );
        assert_eq!(
            response.headers.get("Vary").map(String::as_str),
            Some("Origin")
        );
    }

    #[test]
    fn the_modifier_and_the_error_hook_reach_the_response_pass() {
        let mut config = config();
        config.security_headers.enabled = false;
        config.custom_response_modifier = Some(Arc::new(|response: &mut ResponseBits| {
            response.status = 418;
        }));
        let processor = wire(&config).response_processor.expect("processor");
        let mut response = bare_response();
        processor.process(&view(), &mut response, None, std::time::SystemTime::now());
        assert_eq!(response.status, 418);

        // A panicking modifier reports through the config's `on_error`.
        let seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let sink = Arc::clone(&seen);
        config.custom_response_modifier = Some(Arc::new(|_response: &mut ResponseBits| {
            panic!("boom");
        }));
        config.on_error = Some(Arc::new(move |stage, _error, context| {
            sink.lock().expect("sink").push((
                stage.to_owned(),
                context.get("path").cloned().unwrap_or_default(),
            ));
        }));
        let processor = wire(&config).response_processor.expect("processor");
        let mut response = bare_response();
        processor.process(&view(), &mut response, None, std::time::SystemTime::now());
        assert_eq!(response.status, 200, "the unmodified response survives");
        assert_eq!(
            seen.lock().expect("sink").as_slice(),
            [("custom_response_modifier".to_owned(), "/x".to_owned())]
        );
    }

    #[test]
    fn the_agent_feeds_the_event_bus_and_the_metrics_collector() {
        let mut config = config();
        config.agent_enable_events = true;
        config.agent_enable_metrics = true;
        config.enable_enrichment = true;
        let (wiring, sink) = with_agent(&config);
        wiring.telemetry.as_ref().expect("fan-out").start();
        wiring.events.as_ref().expect("bus").send_middleware_event(
            "rate_limited",
            "192.0.2.1",
            "request_blocked",
            "limit",
        );
        assert_eq!(sink.events.load(Ordering::SeqCst), 1);
        let metrics = wiring.metrics.as_ref().expect("metrics");
        metrics.collect_request_metrics("/x", "GET", Some(0.1), 200);
        assert!(sink.metrics.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn muted_event_types_and_a_disabled_gate_silence_the_bus() {
        let mut config = config();
        config.agent_enable_events = true;
        config.muted_event_types = set(&["rate_limited"]);
        let (wiring, sink) = with_agent(&config);
        let bus = wiring.events.as_ref().expect("bus");
        bus.send_middleware_event("rate_limited", "192.0.2.1", "request_blocked", "limit");
        assert_eq!(sink.events.load(Ordering::SeqCst), 0, "muted");

        config.muted_event_types.clear();
        config.agent_enable_events = false;
        let (wiring, sink) = with_agent(&config);
        wiring.events.as_ref().expect("bus").send_middleware_event(
            "rate_limited",
            "192.0.2.1",
            "request_blocked",
            "limit",
        );
        assert_eq!(sink.events.load(Ordering::SeqCst), 0, "gate off");
    }

    #[test]
    fn otel_and_logfire_are_sinks_of_their_own() {
        let mut config = config();
        config.enable_otel = true;
        assert!(wire(&config).telemetry.is_some());

        config.enable_otel = false;
        config.enable_logfire = true;
        assert!(wire(&config).telemetry.is_none(), "no client, no sink");

        let wiring = Wiring::from_security_config_with(
            &config,
            &WiringOptions {
                agent: None,
                logfire_client: Some(Arc::new(Client)),
            },
        )
        .expect("wired");
        let telemetry = wiring.telemetry.as_ref().expect("fan-out");
        telemetry.start();
        assert!(telemetry.health_check());
        assert!(
            telemetry
                .send_event(&SecurityEvent::new("e", "1.1.1.1", "a", "r", "h"))
                .is_empty()
        );
        assert!(
            telemetry
                .send_metric(&SecurityMetric {
                    timestamp: std::time::SystemTime::now(),
                    metric_type: "request_count".to_owned(),
                    value: 1.0,
                    endpoint: None,
                    tags: std::collections::BTreeMap::new(),
                })
                .is_empty()
        );
        assert!(telemetry.stop().is_empty());
    }

    #[test]
    fn dynamic_rules_poll_the_agent_until_the_handle_drops() {
        let mut config = config();
        config.enable_dynamic_rules = true;
        config.dynamic_rule_interval = 1;
        config.enable_ip_banning = true;
        config.detection_pattern_validation_cache_path = Some(
            std::env::temp_dir()
                .join(format!(
                    "guard-core-wiring-cache-{}.json",
                    std::process::id()
                ))
                .to_string_lossy()
                .into_owned(),
        );
        // Without a sink there is nothing to poll.
        assert!(wire(&config).dynamic_rules.is_none());

        let (wiring, sink) = with_agent(&config);
        let rules = wiring.dynamic_rules.as_ref().expect("driver");
        assert_eq!(rules.interval, Duration::from_secs(1));
        let handle = rules.spawn();
        let polled = (0..300).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            sink.polls.load(Ordering::SeqCst) > 0
        });
        assert!(polled, "the loop polled the agent");
        drop(handle);

        config.enable_dynamic_rules = false;
        let (wiring, _sink) = with_agent(&config);
        assert!(wiring.dynamic_rules.is_none());
    }

    #[test]
    fn the_composite_sink_forwards_every_call() {
        let sink = Arc::new(CountingSink::default());
        let composite = Arc::new(crate::composite::build_composite_handler(
            &config(),
            Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
            None,
        ));
        let adapter = CompositeSink(composite);
        assert_eq!(adapter.handler_name(), "CompositeAgentHandler");
        assert_eq!(sink.handler_name(), "CountingSink");
        adapter.start().expect("start");
        adapter
            .send_event(&SecurityEvent::new("e", "1.1.1.1", "a", "r", "h"))
            .expect("event");
        adapter
            .send_metric(&SecurityMetric {
                timestamp: std::time::SystemTime::now(),
                metric_type: "request_count".to_owned(),
                value: 1.0,
                endpoint: None,
                tags: std::collections::BTreeMap::new(),
            })
            .expect("metric");
        assert_eq!(adapter.get_dynamic_rules().expect("rules"), None);
        assert_eq!(sink.polls.load(Ordering::SeqCst), 1);
        assert!(adapter.health_check());
        adapter.stop().expect("stop");
    }

    #[test]
    fn every_error_renders_and_chains() {
        let ip = IpGateConfig::new(Vec::<String>::new(), ["x"], Vec::<String>::new())
            .expect_err("bad entry");
        let rate = RateLimiter::new(RateLimitConfig {
            rate_limit: 0,
            ..RateLimitConfig::default()
        })
        .expect_err("zero");
        let agent = UserAgentFilter::new(["(a+)+$"]).expect_err("redos");
        let ban = IpBanConfig {
            auto_ban_threshold: 0,
            ..IpBanConfig::default()
        };
        let ban = UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::default(),
            ip_ban: ban,
            passive_mode: false,
        })
        .build()
        .expect_err("threshold");
        let cloud = parse_cloud_selectors(["Nope"]).expect_err("provider");
        let errors = [
            WiringError::from(ip),
            WiringError::from(rate),
            WiringError::from(agent),
            WiringError::from(ban),
            WiringError::from(cloud),
            WiringError::Redis("down".to_owned()),
            WiringError::Geo("x".to_owned()),
        ];
        for (index, error) in errors.iter().enumerate() {
            assert!(!error.to_string().is_empty());
            let chained = std::error::Error::source(error).is_some();
            assert_eq!(chained, index < 5, "{error}");
        }
    }
}
