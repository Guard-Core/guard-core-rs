//! Pipeline-kind conformance suites (spec 4.1.0): the loader, the case
//! engine, and the comparator.
//!
//! The suites replay the reference repo's pipeline harness
//! (`guard-core/specs/fixtures/tools/pipeline_harness.py`) through the Rust
//! family's real stage seams - the same `guard_core_rs` stages the adapters
//! install (`IpGateConfig`, `UserAgentStage`, the geo `check_countries`
//! gate, `RateLimitStage::decide_for_path_observed`) over an in-memory geo
//! stub, redis-free, one fresh engine per case. The comparison follows
//! `specs/fixtures/README.md`: only the keys present in each expected
//! record are compared, fail closed on unknown keys.
//!
//! Deliberately skipped keys (the Go runner's documented precedent):
//!
//! - `events`: the reference captures `(event_type, action_taken)` pairs
//!   from its middleware event bus. The Rust stage composition exposes the
//!   `SecurityEventBus` only on the rate-limit/ban/detection paths, and
//!   with the family's own event vocabulary (`rate_limited`, not the
//!   reference's `dynamic_rule_violation` / `decorator_violation` /
//!   `ip_blocked` / `user_agent_blocked`); the gate, geo, and user-agent
//!   stages emit nothing capturable here. Any case whose only observable
//!   difference is an event record compares clean; every other key still
//!   compares.
//!
//! Where the Rust architecture has no port yet, the case still runs and
//! the diffs land in the fail-closed xfail baseline
//! (`conformance/xfail_baseline.toml`) with the reason. The ported
//! surfaces: the security-headers manager
//! (`guard_core_engine::security_headers`, applied to every blocked and
//! `process_response` answer), CORS (`guard_core_engine::cors`), the
//! response-side `process_response` pass with the behavior-rule engine
//! (`guard_core_rs::process_response` + `guard_core_engine::behavior`,
//! sharing the stages' ban store), and the suspicious-activity `400`
//! answer (the detection feed answers the contract body below the ban
//! threshold). The remaining gap: route `ip_whitelist` /
//! `ip_blacklist`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use guard_core_engine::behavior::{BehaviorTracker, rule_from_config};
use guard_core_engine::cors::{CorsConfig, downgrade_wildcard_credentials};
use guard_core_engine::detect::{self, DetectConfig};
use guard_core_engine::detection_exclusions::{
    self, DetectionExclusionConfig, RouteDetectionExclusions,
};
use guard_core_engine::geo::{
    self, CountryGate, GeoIpHandler, check_countries, generic_list_block_reason,
};
use guard_core_engine::ip_ban::IpBanManager;
use guard_core_engine::ip_gate::{IpGateConfig, IpGateVerdict};
use guard_core_engine::rate_limit::{RateLimitEntry, RouteRateLimits};
use guard_core_engine::security_headers::{
    self as security_headers_engine, CspDirective, HstsConfig, SecurityHeadersConfig,
};
use guard_core_engine::user_agent::UserAgentFilter;
use guard_core_rs::process_response::{RequestBits, ResponseBits, ResponseProcessor};
use guard_core_rs::redact::SensitiveNames;
use guard_core_rs::responses::{OnBlockHook, resolve_error_body};
use guard_core_rs::tower::{
    IpBanConfig, ObservabilityConfig, RateLimitConfig, RateLimitStage, RateLimitStageConfig,
    RequestObservation, ThreatFinding, ViolationCounters,
};
use guard_core_rs::user_agent::{UserAgentStage, UserAgentStageConfig};
use serde::Deserialize;
use serde_json::Value;

use crate::corpus;

/// One pipeline-kind suite file (same envelope as the detect suites).
#[derive(Deserialize)]
pub struct PipelineSuiteFile {
    pub suite: String,
    pub spec_version: String,
    pub engine_version: String,
    pub cases: Vec<PipelineCase>,
}

/// One pipeline case: config overrides, the geo stub table, the route
/// table, the sequential drives, and the expected observation per drive.
#[derive(Deserialize, Clone)]
pub struct PipelineCase {
    pub id: String,
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub geo_countries: BTreeMap<String, String>,
    #[serde(default)]
    pub routes: BTreeMap<String, Value>,
    pub drives: Vec<PipelineDrive>,
    pub expected: Vec<Value>,
}

/// One drive of a pipeline case (the harness `_PipelineRequest` shape).
#[derive(Deserialize, Clone)]
pub struct PipelineDrive {
    pub client_ip: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub url_path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub response_status: Option<u16>,
    #[serde(default)]
    pub response_body: Option<String>,
}

/// Load and validate every `kind: "pipeline"` suite the index lists, with
/// the detect loader's validation rules: suite name, spec and engine
/// version pins, and the declared case count.
pub fn load_pipeline_suites(
    index: &corpus::IndexFile,
) -> Result<Vec<(String, Vec<PipelineCase>)>, String> {
    let dir = corpus::corpus_dir();
    let mut suites = Vec::new();
    for (name, entry) in &index.suites {
        if entry.kind.as_deref() != Some("pipeline") {
            continue;
        }
        let path = dir.join(format!("{name}.json"));
        let raw =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let suite: PipelineSuiteFile =
            serde_json::from_str(&raw).map_err(|e| format!("parse {name}.json: {e}"))?;
        if suite.suite != *name {
            return Err(format!(
                "suite name mismatch: {name}.json declares suite '{}'",
                suite.suite
            ));
        }
        if suite.spec_version != index.spec_version {
            return Err(format!(
                "suite {name} spec_version '{}' does not match index spec_version '{}'",
                suite.spec_version, index.spec_version
            ));
        }
        if suite.engine_version != index.engine_version {
            return Err(format!(
                "suite {name} engine_version '{}' does not match index engine_version '{}'",
                suite.engine_version, index.engine_version
            ));
        }
        if suite.cases.len() != entry.case_count {
            return Err(format!(
                "suite {name} declares {} cases but contains {}",
                entry.case_count,
                suite.cases.len()
            ));
        }
        suites.push((name.clone(), suite.cases));
    }
    Ok(suites)
}

/// The configured engine for one case.
///
/// Everything is built fresh, so each case starts from clean rate-limit
/// windows and an empty ban store (the harness `reset_global_state` +
/// `RateLimitManager.reset` equivalent).
pub struct CaseEngine {
    gate: IpGateConfig,
    geo_gate: CountryGate,
    geo_table: Arc<BTreeMap<String, String>>,
    ua_stage: UserAgentStage,
    rl_stage: RateLimitStage,
    routes: BTreeMap<String, RouteSpec>,
    passive: bool,
    detect_config: DetectConfig,
    payloads: Arc<Mutex<Vec<Value>>>,
    /// The rendered security-header set (`security_headers_manager
    /// .get_headers`); empty when the headers feature is disabled.
    security_headers: BTreeMap<String, String>,
    /// The response-side pass (behavior rules + headers + CORS).
    processor: ResponseProcessor,
}

/// The route table entry: the rate tier the family ports plus the
/// detection-exclusion surface (`detection_exclusions::resolve` +
/// `detection_enabled`) where the family ports that too.
struct RouteSpec {
    rate_limits: Option<RouteRateLimits>,
    exclusions: Option<RouteDetectionExclusions>,
    suspicious_detection: Option<bool>,
}

struct TableHandler {
    table: Arc<BTreeMap<String, String>>,
}

impl GeoIpHandler for TableHandler {
    fn get_country(&self, ip: IpAddr) -> Option<String> {
        self.table.get(&ip.to_string()).cloned()
    }
}

fn str_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn config_value<'a>(config: &'a Value, key: &str) -> Option<&'a Value> {
    config.get(key)
}

fn config_strings(config: &Value, key: &str) -> Vec<String> {
    config_value(config, key).map(str_list).unwrap_or_default()
}

fn config_bool(config: &Value, key: &str, default: bool) -> bool {
    config_value(config, key)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

/// Case-insensitive header lookup (the adapters' header maps).
fn header_value(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

impl CaseEngine {
    /// Build the case engine from the case's config subset. Fails closed on
    /// an invalid list entry or rate-limit value: the reference
    /// `SecurityConfig` accepts every corpus configuration, so a
    /// construction failure can only be a port-side regression.
    ///
    /// # Errors
    ///
    /// A config string the family stages reject (never expected on the
    /// corpus), reported as a divergence by the caller.
    #[allow(clippy::too_many_lines)]
    pub fn new(case: &PipelineCase, detect_config: DetectConfig) -> Result<Self, String> {
        let config = &case.config;

        let gate = IpGateConfig::new(
            config_strings(config, "whitelist"),
            config_strings(config, "blacklist"),
            config_strings(config, "exempt_ips"),
        )
        .map_err(|e| format!("ip gate config: {e}"))?;

        let geo_gate = geo::parse_country_lists(
            config_strings(config, "whitelist_countries"),
            config_strings(config, "blocked_countries"),
        );

        let geo_table = Arc::new(case.geo_countries.clone());

        let passive = config_bool(config, "passive_mode", false);

        let mut rate_limit = RateLimitConfig {
            enable_rate_limiting: config_bool(config, "enable_rate_limiting", true),
            ..RateLimitConfig::default()
        };
        if let Some(value) = config_value(config, "rate_limit").and_then(Value::as_u64) {
            rate_limit.rate_limit =
                u32::try_from(value).map_err(|_| format!("rate_limit {value} out of range"))?;
        }
        if let Some(value) = config_value(config, "rate_limit_window").and_then(Value::as_u64) {
            rate_limit.rate_limit_window = value;
        }
        if let Some(value) =
            config_value(config, "enable_rate_limit_auto_ban").and_then(Value::as_bool)
        {
            rate_limit.enable_rate_limit_auto_ban = value;
        }
        if let Some(entries) =
            config_value(config, "endpoint_rate_limits").and_then(Value::as_object)
        {
            for (path, pair) in entries {
                let entry = endpoint_entry(path, pair)?;
                rate_limit.endpoint_rate_limits.insert(path.clone(), entry);
            }
        }

        let mut ip_ban = IpBanConfig {
            enable_ip_banning: config_bool(config, "enable_ip_banning", false),
            ..IpBanConfig::default()
        };
        if let Some(value) = config_value(config, "auto_ban_threshold").and_then(Value::as_u64) {
            ip_ban.auto_ban_threshold = u32::try_from(value)
                .map_err(|_| format!("auto_ban_threshold {value} out of range"))?;
        }

        let mut custom_error_responses = std::collections::HashMap::new();
        if let Some(entries) =
            config_value(config, "custom_error_responses").and_then(Value::as_object)
        {
            for (status, message) in entries {
                let status: u16 = status
                    .parse()
                    .map_err(|_| format!("custom_error_responses key '{status}': not a status"))?;
                let message = message
                    .as_str()
                    .ok_or("custom_error_responses message must be a string")?;
                custom_error_responses.insert(status, message.to_owned());
            }
        }

        let payloads: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = payloads.clone();
        let hook: OnBlockHook = Arc::new(move |payload| {
            let record = payload_json(
                &payload.check_name,
                &payload.reason,
                &payload.trigger_info,
                payload.passive_mode,
                &payload.client_ip,
                &payload.path,
                &payload.method,
                payload.status_code,
            );
            if let Ok(mut seen) = sink.lock() {
                seen.push(record);
            }
        });

        // The shared ban store: the reference singleton `ip_ban_manager`
        // the behavior dispatch and the pipeline's ban check both see.
        let bans = IpBanManager::new();
        let counters = ViolationCounters::new();

        let rl_stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit,
            ip_ban,
            passive_mode: passive,
            custom_error_responses: custom_error_responses.clone(),
        })
        .on_block(hook)
        .ban_manager(bans.clone(), counters)
        .observability(ObservabilityConfig {
            sensitive: SensitiveNames::default(),
            ..ObservabilityConfig::default()
        })
        .build()
        .map_err(|e| format!("rate limit stage: {e}"))?;

        let ua_stage = UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::new(config_strings(
                config,
                "blocked_user_agents",
            ))
            .map_err(|e| format!("blocked_user_agents: {e}"))?,
            ip_ban: IpBanConfig {
                enable_ip_banning: false,
                ..IpBanConfig::default()
            },
            passive_mode: passive,
        })
        .routes(route_user_agent_filters(case)?)
        .build()
        .map_err(|e| format!("user agent stage: {e}"))?;

        let mut routes = BTreeMap::new();
        for (path, overrides) in &case.routes {
            let limit = overrides.get("rate_limit").and_then(Value::as_u64);
            let window = overrides.get("rate_limit_window").and_then(Value::as_u64);
            let rate_limits = if limit.is_some() || window.is_some() {
                let limit = limit
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| format!("route {path}: rate_limit out of range"))?;
                Some(
                    RouteRateLimits::new(limit, window, None)
                        .map_err(|e| format!("route {path}: {e}"))?,
                )
            } else {
                None
            };
            let list_at = |key: &str| overrides.get(key).map(str_list);
            let exclusions = RouteDetectionExclusions {
                excluded_detection_headers: list_at("excluded_detection_headers"),
                excluded_detection_params: list_at("excluded_detection_params"),
                excluded_detection_body_fields: list_at("excluded_detection_body_fields"),
                enabled_detection_categories: None,
                detection_scan_body: None,
            };
            let exclusions = if overrides.get("excluded_detection_headers").is_some()
                || overrides.get("excluded_detection_params").is_some()
                || overrides.get("excluded_detection_body_fields").is_some()
            {
                Some(exclusions)
            } else {
                None
            };
            routes.insert(
                path.clone(),
                RouteSpec {
                    rate_limits,
                    exclusions,
                    suspicious_detection: overrides
                        .get("enable_suspicious_detection")
                        .and_then(Value::as_bool),
                },
            );
        }

        // The security-headers manager surface: the reference
        // `security_headers` dict (absent on the config = the
        // `SecurityConfig` default block), resolved once per case the way
        // the reference resolves `get_headers` against the config.
        let headers_config = match config_value(config, "security_headers") {
            Some(value) => security_headers_config_from(value)?,
            None => SecurityHeadersConfig::reference_default(),
        };
        let security_headers = security_headers_engine::security_headers(&headers_config);

        // The CORS config (`_compute_cors_config`): a disabled switch
        // resolves to no CORS surface; wildcard + credentials downgrades
        // at resolution time.
        let cors = if config_bool(config, "enable_cors", false) {
            let mut cors = CorsConfig {
                enabled: true,
                allow_origins: config_strings(config, "cors_allow_origins"),
                allow_methods: {
                    let methods = config_strings(config, "cors_allow_methods");
                    if methods.is_empty() {
                        CorsConfig::default().allow_methods
                    } else {
                        methods
                    }
                },
                allow_headers: {
                    let headers = config_strings(config, "cors_allow_headers");
                    if headers.is_empty() {
                        CorsConfig::default().allow_headers
                    } else {
                        headers
                    }
                },
                allow_credentials: config_bool(config, "cors_allow_credentials", false),
            };
            if cors.allow_origins.is_empty() {
                cors.allow_origins = CorsConfig::default().allow_origins;
            }
            downgrade_wildcard_credentials(&mut cors);
            Some(cors)
        } else {
            None
        };

        // The behavior-rule engine: the reference `BehaviorTracker` plus
        // the global return_pattern rules, sharing the ban store with the
        // pipeline stages.
        let global_rules = config_value(config, "global_behavior_rules")
            .and_then(Value::as_array)
            .map(|rules| {
                rules
                    .iter()
                    .map(|cfg| {
                        rule_from_config(cfg).ok_or_else(|| format!("invalid behavior rule: {cfg}"))
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .transpose()?;
        let scan_response_body = config_bool(config, "behavior_scan_response_body", false);
        let processor = ResponseProcessor::new(
            Some(headers_config),
            cors,
            global_rules.unwrap_or_default(),
            Arc::new(Mutex::new(BehaviorTracker::new())),
            bans,
            scan_response_body,
            262_144,
            passive,
        );

        Ok(Self {
            gate,
            geo_gate,
            geo_table,
            ua_stage,
            rl_stage,
            routes,
            passive,
            detect_config,
            payloads,
            security_headers,
            processor,
        })
    }

    const fn custom_errors(&self) -> &std::collections::HashMap<u16, String> {
        &self.rl_stage.config().custom_error_responses
    }

    /// The pipeline-stage pass over one drive, in the reference order:
    /// global IP gate, geo country rules, user-agent stage, then the
    /// rate-limit stage (bans, tiers, detection feed). Blocked answers
    /// carry the security-header set, exactly like the reference
    /// `create_error_response`.
    #[allow(clippy::too_many_lines)]
    fn drive(&self, drive: &PipelineDrive) -> Observation {
        let mut record = Observation {
            is_exempt: Some(false),
            is_whitelisted: Some(false),
            ..Observation::default()
        };
        let Ok(ip) = IpAddr::from_str(&drive.client_ip) else {
            record.status = Some(0);
            record.body = Some(format!("invalid client ip: {}", drive.client_ip));
            return record;
        };
        let path = drive.url_path.as_deref().unwrap_or("/api");
        let method = drive.method.as_deref().unwrap_or("GET");

        if drive.stage.as_deref().unwrap_or("pipeline") == "process_response" {
            // The response-side pass (`ErrorResponseFactory
            // .process_response`): the behavior rules evaluate the
            // produced response (a tripped ban lands in the shared ban
            // store the pipeline drives see), then the security headers
            // and the CORS verdict land on the response. Return rules
            // never modify the response.
            let mut response = ResponseBits {
                status: drive.response_status.unwrap_or(200),
                body: Some(drive.response_body.clone().unwrap_or_else(|| "ok".into())),
                headers: BTreeMap::new(),
            };
            let request = RequestBits {
                method: method.to_owned(),
                url_path: path.to_owned(),
                client_ip: ip.to_string(),
                origin: header_value(&drive.headers, "origin"),
            };
            self.processor
                .process(&request, &mut response, None, SystemTime::now());
            record.status = Some(response.status);
            record.body = response.body;
            record.headers = response.headers;
            return record;
        }

        let handler = TableHandler {
            table: self.geo_table.clone(),
        };

        // 1. The global IP gate (whitelist / blacklist / exempt).
        let decision = match self.gate.evaluate(ip) {
            // The reference records the skip flags only once the request
            // has passed the geo stage (a country-blocked exempt IP leaves
            // both flags unset), so the flags land on the record below.
            IpGateVerdict::Allowed(decision) => Some(decision),
            IpGateVerdict::Denied(_) => {
                // The reference denial reason is the generic list reason
                // for both the blacklist and the restrictive-whitelist
                // mode (`IP {ip} not in global allowlist/blocklist`).
                let reason = format!("IP not allowed: {ip} - {}", generic_list_block_reason(ip));
                self.record_gate_block(&mut record, ip, path, method, &reason);
                return record;
            }
        };

        // 2. The geo country rules (a global whitelist match skips them,
        //    the reference `skip_countries` flag).
        let whitelisted = decision.is_some_and(|d| d.is_whitelisted);
        if let Some(block) = check_countries(ip, &self.geo_gate, &handler, whitelisted) {
            let reason = format!("IP not allowed: {ip} - {}", block.reason);
            self.record_gate_block(&mut record, ip, path, method, &reason);
            return record;
        }
        if let Some(decision) = decision {
            record.is_exempt = Some(decision.is_exempt);
            record.is_whitelisted = Some(decision.is_whitelisted);
        }

        // 3. The detection feed result (computed before the stages that
        //    consume it, the way the adapters attach the finding), honoring
        //    the route's detection surface through the engine's
        //    `detection_exclusions` seam.
        let finding = self.scan(drive, self.routes.get(path));

        // 4. The user-agent stage (route filter first, then the global
        //    filter; skipped for a whitelisted or exempt IP).
        let agent = drive
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.as_str());
        if let Some(answer) =
            self.ua_stage
                .decide(Some(ip), decision, Some(path), agent, Some(&finding))
        {
            let status = answer.status.as_u16();
            let body = resolve_error_body(self.custom_errors(), status, answer.body);
            let reason = format!("Blocked user agent: {}", agent.unwrap_or_default());
            self.record_block(
                &mut record,
                status,
                &body,
                ip,
                path,
                method,
                "user_agent",
                &reason,
                "",
            );
            return record;
        }

        // 5. The rate-limit stage (bans, tiers, and the detection feed).
        let observation = RequestObservation {
            method: Some(method.to_owned()),
            url: Some(path.to_owned()),
            user_agent: agent.map(ToOwned::to_owned),
        };
        let route = self
            .routes
            .get(path)
            .and_then(|spec| spec.rate_limits.as_ref());
        if let Some(answer) = self.rl_stage.decide_for_path_observed(
            Some(ip),
            Some(path),
            route,
            decision,
            Some(&finding),
            Some(&observation),
        ) {
            let status = answer.status.as_u16();
            let body = answer
                .custom_body
                .clone()
                .unwrap_or_else(|| answer.body.to_owned());
            record.status = Some(status);
            record.body = Some(body);
            if let Some(retry_after) = answer.retry_after {
                record
                    .headers
                    .insert("Retry-After".into(), retry_after.to_string());
            }
        }

        // Whatever the stage's recorder captured (rate-limit and
        // detection-feed blocks, active or passive) lands on the record.
        if let Ok(mut seen) = self.payloads.lock() {
            record.on_block.extend(seen.drain(..));
        }

        // Every rendered (non-passive) answer carries the security-header
        // set, exactly like the reference `create_error_response`.
        if record.status.is_some() {
            for (name, value) in &self.security_headers {
                record.headers.insert(name.clone(), value.clone());
            }
        }

        record
    }

    /// Render one gate/geo/user-agent block answer: the family contract
    /// status and body (with the custom-error override), the passive-mode
    /// null answer, and the payload the reference hook receives. The
    /// payload is recorded directly (the stage-attached recorder only sees
    /// stage-internal blocks).
    #[allow(clippy::too_many_arguments)]
    fn record_block(
        &self,
        record: &mut Observation,
        status: u16,
        body: &str,
        ip: IpAddr,
        path: &str,
        method: &str,
        check_name: &str,
        reason: &str,
        trigger_info: &str,
    ) {
        let render_status = if self.passive { None } else { Some(status) };
        record.status = render_status;
        if render_status.is_some() {
            record.body = Some(body.to_owned());
            // The reference `create_error_response` applies the
            // security-header set to every block answer.
            for (name, value) in &self.security_headers {
                record.headers.insert(name.clone(), value.clone());
            }
        }
        record.on_block.push(payload_json(
            check_name,
            reason,
            trigger_info,
            self.passive,
            &ip.to_string(),
            path,
            method,
            render_status,
        ));
    }

    fn record_gate_block(
        &self,
        record: &mut Observation,
        ip: IpAddr,
        path: &str,
        method: &str,
        reason: &str,
    ) {
        self.record_block(
            record,
            403,
            "Forbidden",
            ip,
            path,
            method,
            "ip_security",
            reason,
            "",
        );
    }

    /// Run the engine's real detection over the body and the header values
    /// (the reference scans the same surfaces) and translate the verdict to
    /// the family `ThreatFinding`. `trigger_info` composes the reference
    /// wording from the engine's first matched regex pattern per source.
    fn scan(&self, drive: &PipelineDrive, route: Option<&RouteSpec>) -> ThreatFinding {
        // `enable_suspicious_detection = false` on the route: no finding at
        // all (the reference decorator's detection toggle).
        if !detection_exclusions::detection_enabled(
            true,
            route.and_then(|r| r.suspicious_detection),
        ) {
            return ThreatFinding::default();
        }
        let resolved = detection_exclusions::resolve(
            None::<&DetectionExclusionConfig>,
            route.and_then(|r| r.exclusions.as_ref()),
        );

        let mut sources: Vec<(String, String, &'static [&'static str])> = Vec::new();
        if resolved.scan_body
            && let Some(body) = drive.body.as_deref().filter(|body| !body.is_empty())
        {
            sources.push(("request_body".to_owned(), body.to_owned(), &[]));
        }
        let mut names: Vec<&String> = drive.headers.keys().collect();
        names.sort();
        for name in names {
            // The reference's header maps lowercase the keys, so the
            // detection trigger label reports the lowercase name
            // (`Header 'x-skip-scan'`), even for a mixed-case wire name.
            let lower_name = name.to_ascii_lowercase();
            let skip: &'static [&'static str] = if resolved.excluded_headers.contains(&lower_name) {
                detection_exclusions::excluded_header_skip_categories(name, &drive.headers[name])
            } else {
                &[]
            };
            sources.push((lower_name, drive.headers[name].clone(), skip));
        }

        let mut categories: Vec<String> = Vec::new();
        let mut trigger_info = String::new();
        for (context, content, skip_categories) in &sources {
            let scan_context = if *context == "request_body" {
                "request_body"
            } else {
                "header"
            };
            let verdict = detect::detect(content, scan_context, &self.detect_config);
            if !verdict.is_threat {
                continue;
            }
            let mut contributing: Vec<String> = Vec::new();
            for threat in &verdict.threats {
                if let detect::Threat::Regex(regex) = threat
                    && !skip_categories.contains(&regex.category.as_str())
                    && !contributing.contains(&regex.category.clone())
                {
                    contributing.push(regex.category.clone());
                }
            }
            if contributing.is_empty() {
                // The reference's per-value category filter is terminal:
                // a threat whose categories are all filtered out ends the
                // scan clean.
                break;
            }
            for category in contributing {
                if !categories.contains(&category) {
                    categories.push(category);
                }
            }
            if trigger_info.is_empty()
                && let Some(detect::Threat::Regex(regex)) = verdict.threats.first()
            {
                let label = if scan_context == "request_body" {
                    "Request body".to_owned()
                } else {
                    format!("Header '{context}'")
                };
                trigger_info = format!("{label}: Value matched pattern '{}'", regex.pattern);
            }
        }

        ThreatFinding {
            is_threat: !categories.is_empty(),
            categories,
            trigger_info,
        }
    }
}

/// Parse the corpus `security_headers` dict into the engine config (the
/// `SecurityConfig.security_headers` subset the harness applies verbatim).
fn security_headers_config_from(value: &Value) -> Result<SecurityHeadersConfig, String> {
    let dict = value.as_object().ok_or("security_headers: not an object")?;
    let str_field = |name: &str| {
        dict.get(name).map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("security_headers.{name}: not a string"))
        })
    };
    let custom = match dict.get("custom") {
        Some(Value::Null) | None => BTreeMap::new(),
        Some(value) => {
            let entries = value
                .as_object()
                .ok_or("security_headers.custom: not an object")?;
            entries
                .iter()
                .map(|(name, value)| {
                    let value = value
                        .as_str()
                        .ok_or_else(|| format!("security_headers.custom.{name}: not a string"))?;
                    Ok((name.clone(), value.to_owned()))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()?
        }
    };
    let csp = match dict.get("csp") {
        Some(Value::Null) | None => Vec::new(),
        Some(value) => {
            let directives = value
                .as_object()
                .ok_or("security_headers.csp: not an object")?;
            directives
                .iter()
                .map(|(name, sources)| {
                    Ok(CspDirective {
                        name: name.clone(),
                        sources: str_list(sources),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?
        }
    };
    let hsts = match dict.get("hsts") {
        Some(Value::Null) | None => None,
        Some(value) => {
            let hsts = value
                .as_object()
                .ok_or("security_headers.hsts: not an object")?;
            Some(HstsConfig {
                max_age: hsts.get("max_age").and_then(Value::as_u64),
                include_subdomains: hsts
                    .get("include_subdomains")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                preload: hsts
                    .get("preload")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
    };
    let config = SecurityHeadersConfig {
        enabled: dict.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        hsts,
        csp,
        frame_options: str_field("frame_options").transpose()?,
        content_type_options: str_field("content_type_options").transpose()?,
        xss_protection: str_field("xss_protection").transpose()?,
        referrer_policy: str_field("referrer_policy").transpose()?,
        permissions_policy: str_field("permissions_policy").transpose()?,
        custom,
    };
    config
        .validate()
        .map_err(|e| format!("security_headers: {e}"))?;
    Ok(config)
}

fn endpoint_entry(path: &str, pair: &Value) -> Result<RateLimitEntry, String> {
    let Some(pair) = pair.as_array() else {
        return Err(format!(
            "endpoint_rate_limits[{path}]: want [limit, window]"
        ));
    };
    let (Some(limit), Some(window)) = (pair.first(), pair.get(1)) else {
        return Err(format!(
            "endpoint_rate_limits[{path}]: want [limit, window]"
        ));
    };
    let limit = limit
        .as_u64()
        .ok_or_else(|| format!("endpoint_rate_limits[{path}]: limit must be a number"))?;
    let window = window
        .as_u64()
        .ok_or_else(|| format!("endpoint_rate_limits[{path}]: window must be a number"))?;
    let requests = u32::try_from(limit)
        .map_err(|_| format!("endpoint_rate_limits[{path}]: limit {limit} out of range"))?;
    RateLimitEntry::new(requests, window).map_err(|e| format!("endpoint_rate_limits[{path}]: {e}"))
}

/// Compile the corpus route tables' `blocked_user_agents` into the family's
/// `RouteUserAgentFilters` seam (consulted before the global filter, as in
/// the reference).
fn route_user_agent_filters(
    case: &PipelineCase,
) -> Result<guard_core_rs::user_agent::RouteUserAgentFilters, String> {
    let mut filters: BTreeMap<String, Arc<UserAgentFilter>> = BTreeMap::new();
    for (path, overrides) in &case.routes {
        let patterns = overrides
            .get("blocked_user_agents")
            .map(str_list)
            .unwrap_or_default();
        if !patterns.is_empty() {
            let filter = UserAgentFilter::new(patterns)
                .map_err(|e| format!("route {path} blocked_user_agents: {e}"))?;
            filters.insert(path.clone(), Arc::new(filter));
        }
    }
    Ok(Arc::new(move |path: &str| filters.get(path).cloned()))
}

#[allow(clippy::too_many_arguments)]
fn payload_json(
    check_name: &str,
    reason: &str,
    trigger_info: &str,
    passive_mode: bool,
    client_ip: &str,
    path: &str,
    method: &str,
    status_code: Option<u16>,
) -> Value {
    serde_json::json!({
        "check_name": check_name,
        "reason": reason,
        "trigger_info": trigger_info,
        "passive_mode": passive_mode,
        "client_ip": client_ip,
        "path": path,
        "method": method,
        "status_code": status_code,
    })
}

/// One observed drive, the harness record shape.
#[derive(Debug, Default, Clone)]
pub struct Observation {
    pub status: Option<u16>,
    pub body: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub is_exempt: Option<bool>,
    pub is_whitelisted: Option<bool>,
    pub on_block: Vec<Value>,
}

/// Drive one case start to finish; one observation per drive, same order.
///
/// # Errors
///
/// A case config the family stages reject (never expected on the corpus).
pub fn run_case(
    case: &PipelineCase,
    knobs: &crate::knobs::Knobs,
) -> Result<Vec<Observation>, String> {
    let detect_config = DetectConfig {
        max_content_length: knobs.max_content_length,
        max_full_scan_bytes: knobs.max_truncate_bytes,
        preserve_attack_patterns: knobs.preserve_attack_patterns,
        semantic_threshold: knobs.semantic_threshold,
        threat_score_threshold: knobs.threat_score_threshold,
        // Spec 4.1.0 predates `detection_binary_min_run_length`; the
        // reference default applies (same pin the detect runner makes).
        binary_min_run_length: 16,
    };
    let engine = CaseEngine::new(case, detect_config)?;
    let mut observed = Vec::new();
    for drive in &case.drives {
        observed.push(engine.drive(drive));
    }
    Ok(observed)
}

/// Compare one observation against one expected record.
///
/// Only the keys present in the expected record are compared (the README
/// rule); `events` is the documented skip; any other unrecognized key
/// fails closed.
pub fn compare(observed: &Observation, expected: &Value) -> Vec<String> {
    let Some(expected) = expected.as_object() else {
        return vec!["expected record is not an object".into()];
    };
    let mut diffs = Vec::new();
    for (key, want) in expected {
        match key.as_str() {
            "status" => {
                let got = observed.status.map_or(Value::Null, Value::from);
                if got != *want {
                    diffs.push(format!("status: got {got} want {want}"));
                }
            }
            "body" => {
                let got = observed.body.clone().unwrap_or_default();
                if want.as_str() != Some(got.as_str()) {
                    diffs.push(format!("body: got {got:?} want {want}"));
                }
            }
            "headers" => {
                let Some(want_headers) = want.as_object() else {
                    diffs.push("headers: expected record is not an object".into());
                    continue;
                };
                for (name, want_value) in want_headers {
                    let matches = observed
                        .headers
                        .get(name)
                        .is_some_and(|got_value| want_value.as_str() == Some(got_value.as_str()));
                    if !matches {
                        let got = observed.headers.get(name).map(String::as_str);
                        diffs.push(format!("header {name}: got {got:?} want {want_value}"));
                    }
                }
            }
            "is_exempt" | "is_whitelisted" => {
                let got = if key == "is_exempt" {
                    observed.is_exempt
                } else {
                    observed.is_whitelisted
                };
                if got != want.as_bool() {
                    diffs.push(format!("{key}: got {got:?} want {want}"));
                }
            }
            // The documented skip: the Rust stage composition exposes no
            // reference-vocabulary event-bus capture (see the module docs).
            "events" => {}
            "on_block" => compare_on_block(observed, want, &mut diffs),
            other => diffs.push(format!("unsupported expected key '{other}'")),
        }
    }
    diffs
}

fn compare_on_block(observed: &Observation, want: &Value, diffs: &mut Vec<String>) {
    let Some(want_payloads) = want.as_array() else {
        diffs.push("on_block: expected record is not an array".into());
        return;
    };
    if observed.on_block.len() != want_payloads.len() {
        diffs.push(format!(
            "on_block count: got {} want {}",
            observed.on_block.len(),
            want_payloads.len()
        ));
        return;
    }
    for (index, (got_payload, want_payload)) in
        observed.on_block.iter().zip(want_payloads).enumerate()
    {
        let (Some(got_payload), Some(want_payload)) =
            (got_payload.as_object(), want_payload.as_object())
        else {
            diffs.push(format!("on_block[{index}]: not objects"));
            continue;
        };
        for (payload_key, want_value) in want_payload {
            let got_value = got_payload.get(payload_key);
            let matches = match (payload_key.as_str(), want_value) {
                ("status_code", Value::Null) => got_value.is_none_or(Value::is_null),
                (_, Value::String(want_string)) => {
                    got_value.and_then(Value::as_str) == Some(want_string.as_str())
                }
                (_, Value::Bool(want_bool)) => {
                    got_value.and_then(Value::as_bool) == Some(*want_bool)
                }
                (_, Value::Number(want_number)) => {
                    got_value.and_then(Value::as_u64) == want_number.as_u64()
                }
                _ => false,
            };
            if !matches {
                diffs.push(format!(
                    "on_block[{index}].{payload_key}: got {got_value:?} want {want_value}"
                ));
            }
        }
    }
}

/// Compare a full case: one flat diff vector across the drives, each entry
/// prefixed with the drive index.
///
/// # Errors
///
/// A case config the family stages reject (never expected on the corpus).
pub fn compare_case(
    case: &PipelineCase,
    knobs: &crate::knobs::Knobs,
) -> Result<Vec<String>, String> {
    let observed = run_case(case, knobs)?;
    let mut diffs = Vec::new();
    for (index, (observation, expected)) in observed.iter().zip(case.expected.iter()).enumerate() {
        for diff in compare(observation, expected) {
            diffs.push(format!("drive {index} {diff}"));
        }
    }
    if observed.len() != case.expected.len() {
        diffs.push(format!(
            "observation count: got {} want {}",
            observed.len(),
            case.expected.len()
        ));
    }
    Ok(diffs)
}
