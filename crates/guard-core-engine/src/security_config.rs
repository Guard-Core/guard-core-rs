//! The unified configuration surface: the reference `SecurityConfig`
//! (`guard_core/_security_config_fields.py`, 129 fields) fieldized for the
//! Rust family.
//!
//! Every field carries the reference default in [`SecurityConfig::default`]
//! and every reference constraint in [`SecurityConfig::validate`] (the
//! pydantic `gt`/`ge`/`le` bounds, the IP-or-CIDR list parsing, and the
//! cross-field agent rules). Validation collects every violation into one
//! [`SecurityConfigError`] (the reference raises per-field pydantic
//! errors; the engine answers with the full problem list, fail-closed).
//!
//! The four seams the reference types as callables/handlers map onto
//! engine-native types:
//!
//! | Python field | Rust type |
//! |---|---|
//! | `geo_ip_handler: GeoIPHandler` | `Arc<dyn GeoIpHandler>` ([`crate::geo`]) |
//! | `custom_request_check` | `CustomRequestFn` ([`crate::custom_checks`]) |
//! | `auth_verifier` | `AuthVerifier` ([`crate::headers_auth`]) |
//! | `cloud_ip_store: CloudIpStoreProtocol` | `Arc<dyn CloudRangeStore>` ([`crate::cloud_fetch`]) |
//! | `on_block` | `OnBlockHook` ([`crate::payload`]) |
//! | `on_error` | `OnErrorFn` ([`crate::payload`]) |
//! | `custom_response_modifier` | `ResponseModifierFn` ([`crate::payload`]) |
//!
//! The `agent_*` group is carried as data (the fields exist here for
//! parity; the wiring into `guard-agent-rs`'s `AgentConfig` is the
//! adapter lane's R5 seam).
//!
//! # Example
//!
//! ```
//! use guard_core_engine::security_config::SecurityConfig;
//!
//! let mut config = SecurityConfig::default();
//! assert!(config.validate().is_ok());
//!
//! config.auto_ban_threshold = 0;
//! let error = config.validate().unwrap_err();
//! assert!(error
//!     .problems
//!     .iter()
//!     .any(|problem| problem.contains("auto_ban_threshold")));
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::behavior::BehaviorRule;
use crate::cloud_fetch::CloudRangeStore;
use crate::custom_checks::CustomRequestFn;
use crate::geo::GeoIpHandler;
use crate::headers_auth::AuthVerifier;
use crate::ip_ban::{IpBanConfig, ThreatBanEntry};
use crate::payload::{OnBlockHook, OnErrorFn, ResponseModifierFn};
use crate::security_headers::SecurityHeadersConfig;

/// The reference detection-category set
/// (`ALL_DETECTION_CATEGORIES`, 19 categories) -
/// [`SecurityConfig::enabled_detection_categories`]'s default.
pub const ALL_DETECTION_CATEGORIES: [&str; 19] = [
    "xss",
    "sqli",
    "dir_traversal",
    "path_traversal",
    "cmd_injection",
    "file_inclusion",
    "ldap",
    "xml",
    "ssrf",
    "nosql",
    "file_upload",
    "template",
    "http_split",
    "sensitive_file",
    "cms_probing",
    "recon",
    "proto_pollution",
    "code_injection",
    "deserialization",
];

/// A log-severity knob value (the reference `Literal['INFO', 'DEBUG',
/// 'WARNING', 'ERROR', 'CRITICAL']`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// `INFO`.
    Info,
    /// `DEBUG`.
    Debug,
    /// `WARNING`.
    Warning,
    /// `ERROR`.
    Error,
    /// `CRITICAL`.
    Critical,
}

impl LogLevel {
    /// The reference literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Critical => "CRITICAL",
        }
    }
}

/// The log-line format knob (the reference `Literal['text', 'json']`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// `text` (the default fixed-format lines).
    Text,
    /// `json` (the structured record formatters).
    Json,
}

impl LogFormat {
    /// The reference literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

/// The agent buffer overflow posture (the reference
/// `Literal['drop', 'block', 'raise']`), `None` defers to the agent's own
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferOverflowPolicy {
    /// `drop`: discard the oldest entry.
    Drop,
    /// `block`: backpressure the caller.
    Block,
    /// `raise`: surface the overflow.
    Raise,
}

impl BufferOverflowPolicy {
    /// The reference literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Block => "block",
            Self::Raise => "raise",
        }
    }
}

/// The unified configuration surface (the reference `SecurityConfig`).
///
/// Construct with [`SecurityConfig::default`] (every field at the
/// reference default) or `..Default::default()` struct-update, then
/// [`SecurityConfig::validate`] before use.
// The boolean count is the reference fieldization, not a design smell:
// the 129-field pydantic model carries exactly these toggles.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone)]
pub struct SecurityConfig {
    /// `trusted_proxies`: proxy IPs or CIDR ranges for X-Forwarded-For
    /// (the literal `unix` is additionally accepted, the reference's
    /// `allow_unix`).
    pub trusted_proxies: Vec<String>,
    /// `trusted_proxy_depth`: how many proxies to expect in the
    /// X-Forwarded-For chain (at least 1).
    pub trusted_proxy_depth: u32,
    /// `trust_x_forwarded_proto`.
    pub trust_x_forwarded_proto: bool,
    /// `passive_mode`: log-only, nothing blocks.
    pub passive_mode: bool,
    /// `geo_ip_handler`.
    pub geo_ip_handler: Option<Arc<dyn GeoIpHandler>>,
    /// `enable_redis`.
    pub enable_redis: bool,
    /// `redis_url`.
    pub redis_url: Option<String>,
    /// `redis_prefix`.
    pub redis_prefix: String,
    /// `redis_socket_connect_timeout` (seconds; `Some` must be positive).
    pub redis_socket_connect_timeout: Option<f64>,
    /// `redis_socket_timeout` (seconds; `Some` must be positive).
    pub redis_socket_timeout: Option<f64>,
    /// `redis_health_check_interval` (seconds; 0 disables).
    pub redis_health_check_interval: u64,
    /// `redis_max_connections` (`Some` must be at least 1).
    pub redis_max_connections: Option<u64>,
    /// `redis_retries` (the type carries the at-least-0 bound).
    pub redis_retries: u32,
    /// `whitelist`: restrictive when non-empty (IPs or CIDR ranges).
    pub whitelist: Option<Vec<String>>,
    /// `blacklist`.
    pub blacklist: Vec<String>,
    /// `exempt_ips`.
    pub exempt_ips: Vec<String>,
    /// `whitelist_countries`.
    pub whitelist_countries: BTreeSet<String>,
    /// `blocked_countries`.
    pub blocked_countries: BTreeSet<String>,
    /// `blocked_user_agents`.
    pub blocked_user_agents: Vec<String>,
    /// `auto_ban_threshold` (at least 1).
    pub auto_ban_threshold: u32,
    /// `auto_ban_duration` (seconds, at least 1).
    pub auto_ban_duration: u64,
    /// `threat_ban_config`: per-category threshold/duration overrides.
    pub threat_ban_config: BTreeMap<String, ThreatBanEntry>,
    /// `enable_rate_limit_auto_ban`.
    pub enable_rate_limit_auto_ban: bool,
    /// `global_behavior_rules`.
    pub global_behavior_rules: Vec<BehaviorRule>,
    /// `behavior_scan_response_body`.
    pub behavior_scan_response_body: bool,
    /// `behavior_max_response_body_inspect_bytes` (1024..=10485760).
    pub behavior_max_response_body_inspect_bytes: usize,
    /// `body_read_timeout` (seconds, `0 < t <= 30`).
    pub body_read_timeout: f64,
    /// `sync_body_read_max_concurrent` (1..=10000).
    pub sync_body_read_max_concurrent: usize,
    /// `custom_log_file`.
    pub custom_log_file: Option<String>,
    /// `log_suspicious_level`.
    pub log_suspicious_level: Option<LogLevel>,
    /// `log_request_level`.
    pub log_request_level: Option<LogLevel>,
    /// `log_country_check_level`.
    pub log_country_check_level: Option<LogLevel>,
    /// `log_format`.
    pub log_format: LogFormat,
    /// `custom_error_responses`: status code to body override.
    pub custom_error_responses: BTreeMap<u16, String>,
    /// `rate_limit` (the default-window request count).
    pub rate_limit: u32,
    /// `rate_limit_window` (seconds).
    pub rate_limit_window: u64,
    /// `enforce_https`.
    pub enforce_https: bool,
    /// `security_headers`.
    pub security_headers: SecurityHeadersConfig,
    /// `custom_request_check`.
    pub custom_request_check: Option<CustomRequestFn>,
    /// `auth_verifier`.
    pub auth_verifier: Option<AuthVerifier>,
    /// `custom_response_modifier`.
    pub custom_response_modifier: Option<ResponseModifierFn>,
    /// `on_block`.
    pub on_block: Option<OnBlockHook>,
    /// `on_error`.
    pub on_error: Option<OnErrorFn>,
    /// `enable_cors`.
    pub enable_cors: bool,
    /// `cors_allow_origins`.
    pub cors_allow_origins: Vec<String>,
    /// `cors_allow_methods`.
    pub cors_allow_methods: Vec<String>,
    /// `cors_allow_headers`.
    pub cors_allow_headers: Vec<String>,
    /// `cors_allow_credentials`.
    pub cors_allow_credentials: bool,
    /// `cors_expose_headers`.
    pub cors_expose_headers: Vec<String>,
    /// `cors_max_age` (seconds).
    pub cors_max_age: u64,
    /// `block_cloud_providers`.
    pub block_cloud_providers: Option<BTreeSet<String>>,
    /// `cloud_ip_refresh_interval` (seconds, 60..=86400).
    pub cloud_ip_refresh_interval: u64,
    /// `lazy_init`.
    pub lazy_init: bool,
    /// `geo_ip_db_max_age` (seconds, 3600..=604800).
    pub geo_ip_db_max_age: u64,
    /// `cloud_ip_store`.
    pub cloud_ip_store: Option<Arc<dyn CloudRangeStore>>,
    /// `exclude_paths` (the framework's own docs/static paths).
    pub exclude_paths: Vec<String>,
    /// `enable_ip_banning`.
    pub enable_ip_banning: bool,
    /// `enable_rate_limiting`.
    pub enable_rate_limiting: bool,
    /// `enable_penetration_detection`.
    pub enable_penetration_detection: bool,
    /// `fail_secure`.
    pub fail_secure: bool,
    /// `redis_fail_open`.
    pub redis_fail_open: bool,
    /// `route_resolution_strict`.
    pub route_resolution_strict: bool,
    /// `ipinfo_token`.
    pub ipinfo_token: Option<String>,
    /// `ipinfo_db_path`.
    pub ipinfo_db_path: Option<PathBuf>,
    /// `enable_agent`.
    pub enable_agent: bool,
    /// `agent_api_key` (required when `enable_agent`).
    pub agent_api_key: Option<String>,
    /// `agent_strict`.
    pub agent_strict: bool,
    /// `agent_endpoint`.
    pub agent_endpoint: String,
    /// `agent_project_id`.
    pub agent_project_id: Option<String>,
    /// `agent_buffer_size`.
    pub agent_buffer_size: usize,
    /// `agent_flush_interval` (seconds).
    pub agent_flush_interval: u64,
    /// `agent_enable_events`.
    pub agent_enable_events: bool,
    /// `agent_enable_metrics`.
    pub agent_enable_metrics: bool,
    /// `agent_timeout` (seconds).
    pub agent_timeout: u64,
    /// `agent_retry_attempts`.
    pub agent_retry_attempts: u32,
    /// `agent_project_encryption_key`.
    pub agent_project_encryption_key: Option<String>,
    /// `agent_guard_version`.
    pub agent_guard_version: Option<String>,
    /// `agent_high_watermark_ratio` (`Some` must be in `(0, 1]`).
    pub agent_high_watermark_ratio: Option<f64>,
    /// `agent_max_concurrent_flushes` (`Some` must be at least 1).
    pub agent_max_concurrent_flushes: Option<u64>,
    /// `agent_buffer_overflow_policy`.
    pub agent_buffer_overflow_policy: Option<BufferOverflowPolicy>,
    /// `agent_backoff_factor` (`Some` must be positive).
    pub agent_backoff_factor: Option<f64>,
    /// `agent_sensitive_headers`.
    pub agent_sensitive_headers: Option<Vec<String>>,
    /// `agent_max_payload_size`.
    pub agent_max_payload_size: Option<u64>,
    /// `agent_compression_enabled`.
    pub agent_compression_enabled: Option<bool>,
    /// `agent_compression_threshold`.
    pub agent_compression_threshold: Option<u64>,
    /// `agent_install_id`.
    pub agent_install_id: Option<String>,
    /// `agent_payload_signing_secret`.
    pub agent_payload_signing_secret: Option<String>,
    /// `enable_dynamic_rules` (requires `enable_agent`).
    pub enable_dynamic_rules: bool,
    /// `dynamic_rule_interval` (seconds, at least 60).
    pub dynamic_rule_interval: u64,
    /// `dynamic_rules_cache_path`.
    pub dynamic_rules_cache_path: Option<PathBuf>,
    /// `agent_status_interval` (seconds, 60..=86400).
    pub agent_status_interval: u64,
    /// `emergency_mode`.
    pub emergency_mode: bool,
    /// `emergency_whitelist`.
    pub emergency_whitelist: Vec<String>,
    /// `endpoint_rate_limits`: path pattern to (count, window seconds).
    pub endpoint_rate_limits: BTreeMap<String, (u32, u64)>,
    /// `detection_compiler_timeout` (seconds, 0.1..=10.0).
    pub detection_compiler_timeout: f64,
    /// `detection_pattern_validation_cache_path`.
    pub detection_pattern_validation_cache_path: Option<String>,
    /// `detection_max_content_length` (1000..=100000).
    pub detection_max_content_length: usize,
    /// `detection_max_body_inspect_bytes` (1024..=10485760).
    pub detection_max_body_inspect_bytes: usize,
    /// `detection_max_scan_values` (2..=100000).
    pub detection_max_scan_values: usize,
    /// `detection_max_scan_chars` (1024..=262144).
    pub detection_max_scan_chars: usize,
    /// `detection_max_json_depth` (1..=1000).
    pub detection_max_json_depth: usize,
    /// `detection_binary_min_run_length` (4..=1024).
    pub detection_binary_min_run_length: usize,
    /// `detection_preserve_attack_patterns`.
    pub detection_preserve_attack_patterns: bool,
    /// `detection_semantic_threshold` (0.0..=1.0).
    pub detection_semantic_threshold: f64,
    /// `detection_anomaly_threshold` (1.0..=10.0).
    pub detection_anomaly_threshold: f64,
    /// `detection_slow_pattern_threshold` (0.01..=1.0).
    pub detection_slow_pattern_threshold: f64,
    /// `detection_monitor_history_size` (100..=10000).
    pub detection_monitor_history_size: usize,
    /// `detection_max_tracked_patterns` (100..=5000).
    pub detection_max_tracked_patterns: usize,
    /// `detection_anomaly_emission_cooldown` (seconds, 1.0..=3600.0).
    pub detection_anomaly_emission_cooldown: f64,
    /// `detection_min_samples_for_anomaly` (10..=1000).
    pub detection_min_samples_for_anomaly: usize,
    /// `detection_threat_score_threshold` (0.0..=10.0).
    pub detection_threat_score_threshold: f64,
    /// `muted_event_types`.
    pub muted_event_types: BTreeSet<String>,
    /// `muted_metric_types`.
    pub muted_metric_types: BTreeSet<String>,
    /// `muted_check_logs`.
    pub muted_check_logs: BTreeSet<String>,
    /// `log_sensitive_headers`.
    pub log_sensitive_headers: BTreeSet<String>,
    /// `log_sensitive_params`.
    pub log_sensitive_params: BTreeSet<String>,
    /// `log_sensitive_body_fields`.
    pub log_sensitive_body_fields: BTreeSet<String>,
    /// `enable_otel`.
    pub enable_otel: bool,
    /// `otel_service_name`.
    pub otel_service_name: String,
    /// `otel_exporter_endpoint`.
    pub otel_exporter_endpoint: Option<String>,
    /// `otel_resource_attributes`.
    pub otel_resource_attributes: BTreeMap<String, String>,
    /// `enable_logfire`.
    pub enable_logfire: bool,
    /// `logfire_service_name`.
    pub logfire_service_name: String,
    /// `enable_enrichment` (requires `enable_agent`).
    pub enable_enrichment: bool,
    /// `excluded_detection_headers`.
    pub excluded_detection_headers: BTreeSet<String>,
    /// `excluded_detection_params`.
    pub excluded_detection_params: BTreeSet<String>,
    /// `excluded_detection_body_fields`.
    pub excluded_detection_body_fields: BTreeSet<String>,
    /// `detection_scan_body`.
    pub detection_scan_body: bool,
    /// `enabled_detection_categories`
    /// (defaults to [`ALL_DETECTION_CATEGORIES`]).
    pub enabled_detection_categories: BTreeSet<String>,
}

impl Default for SecurityConfig {
    /// Every field at the reference default
    /// (`guard_core/_security_config_fields.py`); the length is the
    /// 129-field default table itself.
    #[allow(clippy::too_many_lines)]
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            trusted_proxy_depth: 1,
            trust_x_forwarded_proto: false,
            passive_mode: false,
            geo_ip_handler: None,
            enable_redis: true,
            redis_url: Some(String::from("redis://localhost:6379")),
            redis_prefix: String::from("guard_core:"),
            redis_socket_connect_timeout: Some(2.0),
            redis_socket_timeout: Some(2.0),
            redis_health_check_interval: 30,
            redis_max_connections: None,
            redis_retries: 1,
            whitelist: None,
            blacklist: Vec::new(),
            exempt_ips: Vec::new(),
            whitelist_countries: BTreeSet::new(),
            blocked_countries: BTreeSet::new(),
            blocked_user_agents: Vec::new(),
            auto_ban_threshold: 10,
            auto_ban_duration: 3600,
            threat_ban_config: BTreeMap::new(),
            enable_rate_limit_auto_ban: false,
            global_behavior_rules: Vec::new(),
            behavior_scan_response_body: false,
            behavior_max_response_body_inspect_bytes: 262_144,
            body_read_timeout: 3.0,
            sync_body_read_max_concurrent: 64,
            custom_log_file: None,
            log_suspicious_level: Some(LogLevel::Warning),
            log_request_level: None,
            log_country_check_level: Some(LogLevel::Info),
            log_format: LogFormat::Text,
            custom_error_responses: BTreeMap::new(),
            rate_limit: 10,
            rate_limit_window: 60,
            enforce_https: false,
            security_headers: SecurityHeadersConfig::reference_default(),
            custom_request_check: None,
            auth_verifier: None,
            custom_response_modifier: None,
            on_block: None,
            on_error: None,
            enable_cors: false,
            cors_allow_origins: vec![String::from("*")],
            cors_allow_methods: vec![
                String::from("GET"),
                String::from("POST"),
                String::from("PUT"),
                String::from("PATCH"),
                String::from("DELETE"),
                String::from("OPTIONS"),
            ],
            cors_allow_headers: vec![String::from("*")],
            cors_allow_credentials: false,
            cors_expose_headers: Vec::new(),
            cors_max_age: 600,
            block_cloud_providers: None,
            cloud_ip_refresh_interval: 3600,
            lazy_init: true,
            geo_ip_db_max_age: 86_400,
            cloud_ip_store: None,
            exclude_paths: vec![
                String::from("/docs"),
                String::from("/redoc"),
                String::from("/openapi.json"),
                String::from("/openapi.yaml"),
                String::from("/favicon.ico"),
                String::from("/static"),
            ],
            enable_ip_banning: true,
            enable_rate_limiting: true,
            enable_penetration_detection: true,
            fail_secure: true,
            redis_fail_open: false,
            route_resolution_strict: false,
            ipinfo_token: None,
            ipinfo_db_path: Some(PathBuf::from("data/ipinfo/country_asn.mmdb")),
            enable_agent: false,
            agent_api_key: None,
            agent_strict: false,
            agent_endpoint: String::from("https://api.guard-core.com"),
            agent_project_id: None,
            agent_buffer_size: 100,
            agent_flush_interval: 30,
            agent_enable_events: true,
            agent_enable_metrics: true,
            agent_timeout: 30,
            agent_retry_attempts: 3,
            agent_project_encryption_key: None,
            agent_guard_version: None,
            agent_high_watermark_ratio: None,
            agent_max_concurrent_flushes: None,
            agent_buffer_overflow_policy: None,
            agent_backoff_factor: None,
            agent_sensitive_headers: None,
            agent_max_payload_size: None,
            agent_compression_enabled: None,
            agent_compression_threshold: None,
            agent_install_id: None,
            agent_payload_signing_secret: None,
            enable_dynamic_rules: false,
            dynamic_rule_interval: 300,
            dynamic_rules_cache_path: None,
            agent_status_interval: 300,
            emergency_mode: false,
            emergency_whitelist: Vec::new(),
            endpoint_rate_limits: BTreeMap::new(),
            detection_compiler_timeout: 2.0,
            detection_pattern_validation_cache_path: None,
            detection_max_content_length: 10_000,
            detection_max_body_inspect_bytes: 262_144,
            detection_max_scan_values: 512,
            detection_max_scan_chars: 65_536,
            detection_max_json_depth: 32,
            detection_binary_min_run_length: 16,
            detection_preserve_attack_patterns: true,
            detection_semantic_threshold: 0.7,
            detection_anomaly_threshold: 3.0,
            detection_slow_pattern_threshold: 0.1,
            detection_monitor_history_size: 1000,
            detection_max_tracked_patterns: 1000,
            detection_anomaly_emission_cooldown: 60.0,
            detection_min_samples_for_anomaly: 30,
            detection_threat_score_threshold: 1.0,
            muted_event_types: BTreeSet::new(),
            muted_metric_types: BTreeSet::new(),
            muted_check_logs: BTreeSet::new(),
            log_sensitive_headers: BTreeSet::new(),
            log_sensitive_params: BTreeSet::new(),
            log_sensitive_body_fields: BTreeSet::new(),
            enable_otel: false,
            otel_service_name: String::from("guard-core"),
            otel_exporter_endpoint: None,
            otel_resource_attributes: BTreeMap::new(),
            enable_logfire: false,
            logfire_service_name: String::from("guard-core"),
            enable_enrichment: false,
            excluded_detection_headers: BTreeSet::new(),
            excluded_detection_params: BTreeSet::new(),
            excluded_detection_body_fields: BTreeSet::new(),
            detection_scan_body: true,
            enabled_detection_categories: ALL_DETECTION_CATEGORIES
                .iter()
                .map(|category| (*category).to_owned())
                .collect(),
        }
    }
}

impl SecurityConfig {
    /// The reference-default configuration. Validation still runs before
    /// use; the defaults satisfy every constraint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate every reference constraint, collecting all violations.
    ///
    /// The length is the reference constraint list, one check per
    /// pydantic `gt`/`ge`/`le` bound plus the list parsers and the
    /// cross-field agent rules; every violation is collected, none
    /// short-circuits.
    ///
    /// # Errors
    ///
    /// [`SecurityConfigError`] carrying every problem, fail-closed.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), SecurityConfigError> {
        let mut problems = Vec::new();

        if self.trusted_proxy_depth < 1 {
            problems.push("trusted_proxy_depth must be at least 1".to_owned());
        }
        if self
            .redis_socket_connect_timeout
            .is_some_and(|value| value <= 0.0)
        {
            problems.push("redis_socket_connect_timeout must be positive when set".to_owned());
        }
        if self.redis_socket_timeout.is_some_and(|value| value <= 0.0) {
            problems.push("redis_socket_timeout must be positive when set".to_owned());
        }
        if self.redis_max_connections.is_some_and(|value| value < 1) {
            problems.push("redis_max_connections must be at least 1 when set".to_owned());
        }
        if self.auto_ban_threshold < 1 {
            problems.push("auto_ban_threshold must be at least 1".to_owned());
        }
        if self.auto_ban_duration < 1 {
            problems.push("auto_ban_duration must be at least 1".to_owned());
        }
        if !(1024..=10_485_760).contains(&self.behavior_max_response_body_inspect_bytes) {
            problems.push(
                "behavior_max_response_body_inspect_bytes must be between 1024 and 10485760"
                    .to_owned(),
            );
        }
        if self.body_read_timeout <= 0.0 || self.body_read_timeout > 30.0 {
            problems.push("body_read_timeout must be between 0 (exclusive) and 30".to_owned());
        }
        if !(1..=10_000).contains(&self.sync_body_read_max_concurrent) {
            problems.push("sync_body_read_max_concurrent must be between 1 and 10000".to_owned());
        }
        if !(60..=86_400).contains(&self.cloud_ip_refresh_interval) {
            problems.push("cloud_ip_refresh_interval must be between 60 and 86400".to_owned());
        }
        if !(3600..=604_800).contains(&self.geo_ip_db_max_age) {
            problems.push("geo_ip_db_max_age must be between 3600 and 604800".to_owned());
        }
        if self.dynamic_rule_interval < 60 {
            problems.push("dynamic_rule_interval must be at least 60".to_owned());
        }
        if !(60..=86_400).contains(&self.agent_status_interval) {
            problems.push("agent_status_interval must be between 60 and 86400".to_owned());
        }
        if !(0.1..=10.0).contains(&self.detection_compiler_timeout) {
            problems.push("detection_compiler_timeout must be between 0.1 and 10.0".to_owned());
        }
        if !(1000..=100_000).contains(&self.detection_max_content_length) {
            problems
                .push("detection_max_content_length must be between 1000 and 100000".to_owned());
        }
        if !(1024..=10_485_760).contains(&self.detection_max_body_inspect_bytes) {
            problems.push(
                "detection_max_body_inspect_bytes must be between 1024 and 10485760".to_owned(),
            );
        }
        if !(2..=100_000).contains(&self.detection_max_scan_values) {
            problems.push("detection_max_scan_values must be between 2 and 100000".to_owned());
        }
        if !(1024..=262_144).contains(&self.detection_max_scan_chars) {
            problems.push("detection_max_scan_chars must be between 1024 and 262144".to_owned());
        }
        if !(1..=1000).contains(&self.detection_max_json_depth) {
            problems.push("detection_max_json_depth must be between 1 and 1000".to_owned());
        }
        if !(4..=1024).contains(&self.detection_binary_min_run_length) {
            problems.push("detection_binary_min_run_length must be between 4 and 1024".to_owned());
        }
        if !(0.0..=1.0).contains(&self.detection_semantic_threshold) {
            problems.push("detection_semantic_threshold must be between 0.0 and 1.0".to_owned());
        }
        if !(1.0..=10.0).contains(&self.detection_anomaly_threshold) {
            problems.push("detection_anomaly_threshold must be between 1.0 and 10.0".to_owned());
        }
        if !(0.01..=1.0).contains(&self.detection_slow_pattern_threshold) {
            problems
                .push("detection_slow_pattern_threshold must be between 0.01 and 1.0".to_owned());
        }
        if !(100..=10_000).contains(&self.detection_monitor_history_size) {
            problems
                .push("detection_monitor_history_size must be between 100 and 10000".to_owned());
        }
        if !(100..=5000).contains(&self.detection_max_tracked_patterns) {
            problems.push("detection_max_tracked_patterns must be between 100 and 5000".to_owned());
        }
        if !(1.0..=3600.0).contains(&self.detection_anomaly_emission_cooldown) {
            problems.push(
                "detection_anomaly_emission_cooldown must be between 1.0 and 3600.0".to_owned(),
            );
        }
        if !(10..=1000).contains(&self.detection_min_samples_for_anomaly) {
            problems
                .push("detection_min_samples_for_anomaly must be between 10 and 1000".to_owned());
        }
        if !(0.0..=10.0).contains(&self.detection_threat_score_threshold) {
            problems
                .push("detection_threat_score_threshold must be between 0.0 and 10.0".to_owned());
        }
        if self
            .agent_high_watermark_ratio
            .is_some_and(|ratio| ratio <= 0.0 || ratio > 1.0)
        {
            problems
                .push("agent_high_watermark_ratio must be between 0 (exclusive) and 1".to_owned());
        }
        if self
            .agent_max_concurrent_flushes
            .is_some_and(|value| value < 1)
        {
            problems.push("agent_max_concurrent_flushes must be at least 1 when set".to_owned());
        }
        if self.agent_backoff_factor.is_some_and(|value| value <= 0.0) {
            problems.push("agent_backoff_factor must be positive when set".to_owned());
        }

        for (field, entries) in [
            ("whitelist", self.whitelist.as_deref().unwrap_or(&[])),
            ("blacklist", &self.blacklist[..]),
            ("exempt_ips", &self.exempt_ips[..]),
        ] {
            for entry in entries {
                if parse_ip_or_cidr(entry).is_none() {
                    problems.push(format!("{field}: invalid IP or CIDR range ({entry})"));
                }
            }
        }
        for entry in &self.trusted_proxies {
            if entry != "unix" && parse_ip_or_cidr(entry).is_none() {
                problems.push(format!(
                    "trusted_proxies: invalid proxy IP or CIDR range ({entry})"
                ));
            }
        }

        if self.enable_agent && self.agent_api_key.is_none() {
            problems.push("agent_api_key is required when enable_agent is true".to_owned());
        }
        if self.enable_dynamic_rules && !self.enable_agent {
            problems.push("enable_agent must be true when enable_dynamic_rules is true".to_owned());
        }
        if self.enable_enrichment && !self.enable_agent {
            problems.push("enable_enrichment requires enable_agent=true".to_owned());
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(SecurityConfigError { problems })
        }
    }

    /// The `IpBanConfig` view of the ban group (`enable_ip_banning`,
    /// `auto_ban_threshold`, `auto_ban_duration`, `threat_ban_config`).
    #[must_use]
    pub fn ip_ban_config(&self) -> IpBanConfig {
        IpBanConfig {
            enable_ip_banning: self.enable_ip_banning,
            auto_ban_threshold: self.auto_ban_threshold,
            auto_ban_duration: self.auto_ban_duration,
            threat_ban_config: self.threat_ban_config.clone().into_iter().collect(),
        }
    }
}

/// Parse one list entry as an IP address or a CIDR range (the reference
/// `_validate_ip_or_cidr_list` accepts both for every IP list; the prefix
/// length is family-bounded, 32 for v4 and 128 for v6).
fn parse_ip_or_cidr(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    let (address, prefix) = entry.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    let address = address.parse::<IpAddr>().ok()?;
    let max_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    (prefix <= max_prefix).then_some(address)
}

/// Every reference violation at once: the config error
/// [`SecurityConfig::validate`] fails closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityConfigError {
    /// Every violation, field-named.
    pub problems: Vec<String>,
}

impl std::fmt::Display for SecurityConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid SecurityConfig ({} problems)",
            self.problems.len()
        )
    }
}

impl std::error::Error for SecurityConfigError {}

#[cfg(test)]
// The tests construct a default config and mutate one group at a time;
// literal 129-field initializers would be unreadable.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn defaults_satisfy_every_constraint() {
        // Through `new` (the reference constructor shape) and through
        // `Default`: both carry the reference defaults.
        assert!(SecurityConfig::new().validate().is_ok());
        assert!(SecurityConfig::default().validate().is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_reference_default_is_carried() {
        let config = SecurityConfig::default();
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.trusted_proxy_depth, 1);
        assert!(!config.trust_x_forwarded_proto);
        assert!(!config.passive_mode);
        assert!(config.geo_ip_handler.is_none());
        assert!(config.enable_redis);
        assert_eq!(config.redis_url.as_deref(), Some("redis://localhost:6379"));
        assert_eq!(config.redis_prefix, "guard_core:");
        assert_eq!(config.redis_socket_connect_timeout.map(|value| (value - 2.0).abs()), Some(0.0));
        assert_eq!(config.redis_socket_timeout.map(|value| (value - 2.0).abs()), Some(0.0));
        assert_eq!(config.redis_health_check_interval, 30);
        assert_eq!(config.redis_max_connections, None);
        assert_eq!(config.redis_retries, 1);
        assert_eq!(config.whitelist, None);
        assert!(config.blacklist.is_empty());
        assert!(config.exempt_ips.is_empty());
        assert!(config.whitelist_countries.is_empty());
        assert!(config.blocked_countries.is_empty());
        assert!(config.blocked_user_agents.is_empty());
        assert_eq!(config.auto_ban_threshold, 10);
        assert_eq!(config.auto_ban_duration, 3600);
        assert!(config.threat_ban_config.is_empty());
        assert!(!config.enable_rate_limit_auto_ban);
        assert!(config.global_behavior_rules.is_empty());
        assert!(!config.behavior_scan_response_body);
        assert_eq!(config.behavior_max_response_body_inspect_bytes, 262_144);
        assert_eq!((config.body_read_timeout - 3.0).abs(), 0.0);
        assert_eq!(config.sync_body_read_max_concurrent, 64);
        assert_eq!(config.custom_log_file, None);
        assert_eq!(config.log_suspicious_level, Some(LogLevel::Warning));
        assert_eq!(config.log_request_level, None);
        assert_eq!(config.log_country_check_level, Some(LogLevel::Info));
        assert_eq!(config.log_format, LogFormat::Text);
        assert!(config.custom_error_responses.is_empty());
        assert_eq!(config.rate_limit, 10);
        assert_eq!(config.rate_limit_window, 60);
        assert!(!config.enforce_https);
        assert_eq!(
            config.security_headers,
            SecurityHeadersConfig::reference_default()
        );
        assert!(config.custom_request_check.is_none());
        assert!(config.auth_verifier.is_none());
        assert!(config.custom_response_modifier.is_none());
        assert!(config.on_block.is_none());
        assert!(config.on_error.is_none());
        assert!(!config.enable_cors);
        assert_eq!(config.cors_allow_origins, ["*"]);
        assert_eq!(
            config.cors_allow_methods,
            ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        );
        assert_eq!(config.cors_allow_headers, ["*"]);
        assert!(!config.cors_allow_credentials);
        assert!(config.cors_expose_headers.is_empty());
        assert_eq!(config.cors_max_age, 600);
        assert_eq!(config.block_cloud_providers, None);
        assert_eq!(config.cloud_ip_refresh_interval, 3600);
        assert!(config.lazy_init);
        assert_eq!(config.geo_ip_db_max_age, 86_400);
        assert!(config.cloud_ip_store.is_none());
        assert_eq!(
            config.exclude_paths,
            [
                "/docs",
                "/redoc",
                "/openapi.json",
                "/openapi.yaml",
                "/favicon.ico",
                "/static"
            ]
        );
        assert!(config.enable_ip_banning);
        assert!(config.enable_rate_limiting);
        assert!(config.enable_penetration_detection);
        assert!(config.fail_secure);
        assert!(!config.redis_fail_open);
        assert!(!config.route_resolution_strict);
        assert_eq!(config.ipinfo_token, None);
        assert_eq!(
            config.ipinfo_db_path.as_deref(),
            Some(std::path::Path::new("data/ipinfo/country_asn.mmdb"))
        );
        assert!(!config.enable_agent);
        assert_eq!(config.agent_api_key, None);
        assert!(!config.agent_strict);
        assert_eq!(config.agent_endpoint, "https://api.guard-core.com");
        assert_eq!(config.agent_project_id, None);
        assert_eq!(config.agent_buffer_size, 100);
        assert_eq!(config.agent_flush_interval, 30);
        assert!(config.agent_enable_events);
        assert!(config.agent_enable_metrics);
        assert_eq!(config.agent_timeout, 30);
        assert_eq!(config.agent_retry_attempts, 3);
        assert_eq!(config.agent_project_encryption_key, None);
        assert_eq!(config.agent_guard_version, None);
        assert_eq!(config.agent_high_watermark_ratio, None);
        assert_eq!(config.agent_max_concurrent_flushes, None);
        assert_eq!(config.agent_buffer_overflow_policy, None);
        assert_eq!(config.agent_backoff_factor, None);
        assert_eq!(config.agent_sensitive_headers, None);
        assert_eq!(config.agent_max_payload_size, None);
        assert_eq!(config.agent_compression_enabled, None);
        assert_eq!(config.agent_compression_threshold, None);
        assert_eq!(config.agent_install_id, None);
        assert_eq!(config.agent_payload_signing_secret, None);
        assert!(!config.enable_dynamic_rules);
        assert_eq!(config.dynamic_rule_interval, 300);
        assert_eq!(config.dynamic_rules_cache_path, None);
        assert_eq!(config.agent_status_interval, 300);
        assert!(!config.emergency_mode);
        assert!(config.emergency_whitelist.is_empty());
        assert!(config.endpoint_rate_limits.is_empty());
        assert_eq!((config.detection_compiler_timeout - 2.0).abs(), 0.0);
        assert_eq!(config.detection_pattern_validation_cache_path, None);
        assert_eq!(config.detection_max_content_length, 10_000);
        assert_eq!(config.detection_max_body_inspect_bytes, 262_144);
        assert_eq!(config.detection_max_scan_values, 512);
        assert_eq!(config.detection_max_scan_chars, 65_536);
        assert_eq!(config.detection_max_json_depth, 32);
        assert_eq!(config.detection_binary_min_run_length, 16);
        assert!(config.detection_preserve_attack_patterns);
        assert!((config.detection_semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.detection_anomaly_threshold - 3.0).abs() < f64::EPSILON);
        assert!((config.detection_slow_pattern_threshold - 0.1).abs() < f64::EPSILON);
        assert_eq!(config.detection_monitor_history_size, 1000);
        assert_eq!(config.detection_max_tracked_patterns, 1000);
        assert!((config.detection_anomaly_emission_cooldown - 60.0).abs() < f64::EPSILON);
        assert_eq!(config.detection_min_samples_for_anomaly, 30);
        assert_eq!(config.detection_threat_score_threshold, 1.0);
        assert!(config.muted_event_types.is_empty());
        assert!(config.muted_metric_types.is_empty());
        assert!(config.muted_check_logs.is_empty());
        assert!(config.log_sensitive_headers.is_empty());
        assert!(config.log_sensitive_params.is_empty());
        assert!(config.log_sensitive_body_fields.is_empty());
        assert!(!config.enable_otel);
        assert_eq!(config.otel_service_name, "guard-core");
        assert_eq!(config.otel_exporter_endpoint, None);
        assert!(config.otel_resource_attributes.is_empty());
        assert!(!config.enable_logfire);
        assert_eq!(config.logfire_service_name, "guard-core");
        assert!(!config.enable_enrichment);
        assert!(config.excluded_detection_headers.is_empty());
        assert!(config.excluded_detection_params.is_empty());
        assert!(config.excluded_detection_body_fields.is_empty());
        assert!(config.detection_scan_body);
        assert_eq!(
            config.enabled_detection_categories,
            ALL_DETECTION_CATEGORIES
                .iter()
                .map(|category| (*category).to_owned())
                .collect::<BTreeSet<String>>()
        );
    }

    #[test]
    fn the_category_table_is_the_reference_set() {
        assert_eq!(ALL_DETECTION_CATEGORIES.len(), 19);
        assert!(ALL_DETECTION_CATEGORIES.contains(&"xss"));
        assert!(ALL_DETECTION_CATEGORIES.contains(&"deserialization"));
    }

    #[test]
    fn the_log_level_round_trips_the_reference_literals() {
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Warning.as_str(), "WARNING");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn the_log_format_round_trips_the_reference_literals() {
        assert_eq!(LogFormat::Text.as_str(), "text");
        assert_eq!(LogFormat::Json.as_str(), "json");
    }

    #[test]
    fn the_overflow_policy_round_trips_the_reference_literals() {
        assert_eq!(BufferOverflowPolicy::Drop.as_str(), "drop");
        assert_eq!(BufferOverflowPolicy::Block.as_str(), "block");
        assert_eq!(BufferOverflowPolicy::Raise.as_str(), "raise");
    }

    /// Every bound constraint, one mutating case per violation: the error
    /// names the field and validation keeps collecting the rest.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_bound_constraint_names_its_field() {
        type Mutator = Box<dyn Fn(&mut SecurityConfig)>;
        let cases: Vec<(&str, Mutator)> = vec![
            (
                "trusted_proxy_depth",
                Box::new(|config: &mut SecurityConfig| config.trusted_proxy_depth = 0),
            ),
            (
                "redis_socket_connect_timeout",
                Box::new(|config: &mut SecurityConfig| {
                    config.redis_socket_connect_timeout = Some(0.0);
                }),
            ),
            (
                "redis_socket_timeout",
                Box::new(|config: &mut SecurityConfig| config.redis_socket_timeout = Some(-1.0)),
            ),
            (
                "redis_max_connections",
                Box::new(|config: &mut SecurityConfig| config.redis_max_connections = Some(0)),
            ),
            (
                "auto_ban_threshold",
                Box::new(|config: &mut SecurityConfig| config.auto_ban_threshold = 0),
            ),
            (
                "auto_ban_duration",
                Box::new(|config: &mut SecurityConfig| config.auto_ban_duration = 0),
            ),
            (
                "behavior_max_response_body_inspect_bytes",
                Box::new(|config: &mut SecurityConfig| {
                    config.behavior_max_response_body_inspect_bytes = 1023;
                }),
            ),
            (
                "body_read_timeout",
                Box::new(|config: &mut SecurityConfig| config.body_read_timeout = 0.0),
            ),
            (
                "body_read_timeout",
                Box::new(|config: &mut SecurityConfig| config.body_read_timeout = 30.1),
            ),
            (
                "sync_body_read_max_concurrent",
                Box::new(|config: &mut SecurityConfig| {
                    config.sync_body_read_max_concurrent = 0;
                }),
            ),
            (
                "cloud_ip_refresh_interval",
                Box::new(|config: &mut SecurityConfig| config.cloud_ip_refresh_interval = 59),
            ),
            (
                "geo_ip_db_max_age",
                Box::new(|config: &mut SecurityConfig| config.geo_ip_db_max_age = 3599),
            ),
            (
                "dynamic_rule_interval",
                Box::new(|config: &mut SecurityConfig| config.dynamic_rule_interval = 59),
            ),
            (
                "agent_status_interval",
                Box::new(|config: &mut SecurityConfig| config.agent_status_interval = 59),
            ),
            (
                "detection_compiler_timeout",
                Box::new(|config: &mut SecurityConfig| config.detection_compiler_timeout = 0.0),
            ),
            (
                "detection_max_content_length",
                Box::new(|config: &mut SecurityConfig| config.detection_max_content_length = 999),
            ),
            (
                "detection_max_body_inspect_bytes",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_max_body_inspect_bytes = 1023;
                }),
            ),
            (
                "detection_max_scan_values",
                Box::new(|config: &mut SecurityConfig| config.detection_max_scan_values = 1),
            ),
            (
                "detection_max_scan_chars",
                Box::new(|config: &mut SecurityConfig| config.detection_max_scan_chars = 1023),
            ),
            (
                "detection_max_json_depth",
                Box::new(|config: &mut SecurityConfig| config.detection_max_json_depth = 0),
            ),
            (
                "detection_binary_min_run_length",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_binary_min_run_length = 3;
                }),
            ),
            (
                "detection_semantic_threshold",
                Box::new(|config: &mut SecurityConfig| config.detection_semantic_threshold = 1.1),
            ),
            (
                "detection_anomaly_threshold",
                Box::new(|config: &mut SecurityConfig| config.detection_anomaly_threshold = 0.9),
            ),
            (
                "detection_slow_pattern_threshold",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_slow_pattern_threshold = 0.0;
                }),
            ),
            (
                "detection_monitor_history_size",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_monitor_history_size = 99;
                }),
            ),
            (
                "detection_max_tracked_patterns",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_max_tracked_patterns = 99;
                }),
            ),
            (
                "detection_anomaly_emission_cooldown",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_anomaly_emission_cooldown = 0.9;
                }),
            ),
            (
                "detection_min_samples_for_anomaly",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_min_samples_for_anomaly = 9;
                }),
            ),
            (
                "detection_threat_score_threshold",
                Box::new(|config: &mut SecurityConfig| {
                    config.detection_threat_score_threshold = 10.1;
                }),
            ),
            (
                "agent_high_watermark_ratio",
                Box::new(|config: &mut SecurityConfig| {
                    config.agent_high_watermark_ratio = Some(1.1);
                }),
            ),
            (
                "agent_max_concurrent_flushes",
                Box::new(|config: &mut SecurityConfig| {
                    config.agent_max_concurrent_flushes = Some(0);
                }),
            ),
            (
                "agent_backoff_factor",
                Box::new(|config: &mut SecurityConfig| config.agent_backoff_factor = Some(0.0)),
            ),
        ];
        for (field, mutate) in cases {
            let mut config = SecurityConfig::default();
            mutate(&mut config);
            let error = config.validate().unwrap_err();
            assert!(
                error.problems.iter().any(|problem| problem.contains(field)),
                "{field}: {:?}",
                error.problems
            );
        }
    }

    #[test]
    fn the_ip_lists_reject_garbage_and_accept_ips_and_cidrs() {
        let mut config = SecurityConfig::default();
        config.whitelist = Some(vec![String::from("10.0.0.1"), String::from("10.0.0.0/8")]);
        config.blacklist = vec![String::from("2001:db8::1"), String::from("2001:db8::/32")];
        config.exempt_ips = vec![String::from("192.0.2.1")];
        config.trusted_proxies = vec![String::from("unix"), String::from("10.1.0.0/16")];
        assert!(config.validate().is_ok());

        config.exempt_ips = vec![String::from("not-an-ip")];
        let error = config.validate().unwrap_err();
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.contains("exempt_ips"))
        );

        config.trusted_proxies = vec![String::from("also-bad")];
        config.whitelist = Some(vec![String::from("10.0.0.0/99")]);
        let error = config.validate().unwrap_err();
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.contains("trusted_proxies"))
        );
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.contains("whitelist"))
        );
    }

    #[test]
    fn the_agent_cross_rules_hold() {
        let mut config = SecurityConfig::default();
        config.enable_agent = true;
        let error = config.validate().unwrap_err();
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.contains("agent_api_key"))
        );

        let mut config = SecurityConfig::default();
        config.enable_dynamic_rules = true;
        let error = config.validate().unwrap_err();
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.contains("enable_agent"))
        );

        let mut config = SecurityConfig::default();
        config.enable_enrichment = true;
        let error = config.validate().unwrap_err();
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.contains("enable_enrichment"))
        );

        // The satisfied shape: everything the toggles demand is present.
        let mut config = SecurityConfig::default();
        config.enable_agent = true;
        config.agent_api_key = Some(String::from("k"));
        config.enable_dynamic_rules = true;
        config.enable_enrichment = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validation_collects_every_problem_at_once() {
        let mut config = SecurityConfig::default();
        config.auto_ban_threshold = 0;
        config.auto_ban_duration = 0;
        config.enable_dynamic_rules = true;
        let error = config.validate().unwrap_err();
        assert_eq!(error.problems.len(), 3);
        assert_eq!(error.to_string(), "invalid SecurityConfig (3 problems)");
    }

    #[test]
    fn the_ban_group_maps_onto_the_engine_config() {
        let mut config = SecurityConfig::default();
        config.enable_ip_banning = false;
        config.auto_ban_threshold = 5;
        config.auto_ban_duration = 60;
        config.threat_ban_config.insert(
            String::from("rate_limit"),
            ThreatBanEntry {
                threshold: 3,
                duration: 120,
            },
        );
        let ban_config = config.ip_ban_config();
        assert!(!ban_config.enable_ip_banning);
        assert_eq!(ban_config.auto_ban_threshold, 5);
        assert_eq!(ban_config.auto_ban_duration, 60);
        assert_eq!(ban_config.threat_ban_config.len(), 1);
    }
}
