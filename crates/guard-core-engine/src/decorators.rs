//! The reference decorator system (`guard_core/decorators/*.py`): the
//! [`SecurityDecorator`] registry and its mixin method surface, ported
//! method for method.
//!
//! Python applies decorators to route functions and stamps a route id on
//! the callable; Rust has no runtime function attributes, so the idiom is
//! a named route id: every mixin method takes the route id the
//! application chose (the reference derives it from
//! `module.qualname`, the stand-in is the caller's stable name, by
//! convention `"<METHOD> <path>"`), and the registry hands the
//! [`RouteConfig`] carrier to the adapters' `with_route_configs`
//! resolvers. Semantics are the reference's, exactly:
//!
//! - first touch creates the route's [`RouteConfig`] with
//!   `enable_suspicious_detection` seeded from the config's
//!   `enable_penetration_detection` and bumps the revision
//!   (`BaseSecurityDecorator._ensure_route_config`),
//! - every mutation is revision-tracked
//!   (`RouteConfigRevision`),
//! - `bypass` keeps only the reference
//!   [`VALID_BYPASS_CHECKS`] names and drops the rest
//!   (the unknowns are returned to the caller, the reference logs them),
//! - `block_clouds` with no argument blocks every
//!   [`VALID_CLOUD_PROVIDERS`] entry; named entries outside the
//!   reference set are ignored and returned,
//! - `require_auth`/`api_key_auth` conflict with
//!   `require_authorization_header` and fail closed
//!   ([`DecoratorError`]),
//! - `return_monitor`/`behavior_analysis` validate every
//!   `return_pattern` compiles (the reference
//!   `_validate_return_pattern_body_scan`'s compile half),
//! - `honeypot_detection` registers the reference's honeypot validator
//!   (form and JSON trap-field probe over the buffered body, POST/PUT/
//!   PATCH only, `403 "Forbidden"`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::behavior::BehaviorRule;
use crate::custom_checks::{CustomRequestContext, CustomResponse, CustomValidatorFn, ValidatorAnswer};
use crate::headers_auth::AuthVerifier;
use crate::route_config::RouteConfig;

/// The reference `VALID_BYPASS_CHECKS`: the names [`SecurityDecorator::
/// bypass`] keeps.
///
/// The pipeline's coarse query vocabulary: the reference consults
/// `should_bypass_check` exactly at the ip gate (`ip`), the ban arm
/// (`ip_ban`), the cloud-provider check (`clouds`), the rate limiter
/// (`rate_limit`), and the penetration scan (`penetration`), plus the
/// `"all"` wildcard.
pub const VALID_BYPASS_CHECKS: [&str; 6] =
    ["all", "ip_ban", "ip", "clouds", "rate_limit", "penetration"];

/// The reference `VALID_CLOUD_PROVIDERS`
/// (`CloudProvider = Literal["AWS", "GCP", "Azure", "DigitalOcean",
/// "Linode", "Vultr"]`).
pub const VALID_CLOUD_PROVIDERS: [&str; 6] =
    ["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"];

/// Why a decorator factory refused a value: the reference raises
/// `ValueError` on the auth-conflict combinations and on an uncompilable
/// `return_pattern`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoratorError {
    /// The reference error message.
    pub message: String,
}

impl std::fmt::Display for DecoratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DecoratorError {}

fn conflict(message: &'static str) -> DecoratorError {
    DecoratorError {
        message: message.to_owned(),
    }
}

/// The decorator registry (`SecurityDecorator`): the config it reads its
/// defaults from, the per-route [`RouteConfig`]s, and the revision
/// counter every mutation bumps.
#[derive(Clone)]
pub struct SecurityDecorator {
    config: crate::security_config::SecurityConfig,
    route_configs: BTreeMap<String, RouteConfig>,
    revision: u64,
}

impl core::fmt::Debug for SecurityDecorator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityDecorator")
            .field("routes", &self.route_configs.len())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl SecurityDecorator {
    /// Build the decorator over the unified configuration (the reference
    /// `BaseSecurityDecorator.__init__`).
    #[must_use]
    pub const fn new(config: crate::security_config::SecurityConfig) -> Self {
        Self {
            config,
            route_configs: BTreeMap::new(),
            revision: 0,
        }
    }

    /// The revision counter (`route_config_revision`): bumped on every
    /// route creation and every mutation the reference tracks.
    #[must_use]
    pub const fn route_config_revision(&self) -> u64 {
        self.revision
    }

    /// The route's config, if the route was decorated
    /// (`get_route_config`).
    #[must_use]
    pub fn get_route_config(&self, route_id: &str) -> Option<&RouteConfig> {
        self.route_configs.get(route_id)
    }

    /// Every decorated route id.
    pub fn route_ids(&self) -> impl Iterator<Item = &str> {
        self.route_configs.keys().map(String::as_str)
    }

    /// `_ensure_route_config`: first touch creates the route's config
    /// with the reference default
    /// (`enable_suspicious_detection = config.enable_penetration_detection`)
    /// and bumps the revision; later touches return the same config.
    pub fn ensure_route_config(&mut self, route_id: &str) -> &mut RouteConfig {
        if !self.route_configs.contains_key(route_id) {
            let mut config = RouteConfig::default();
            config.enable_suspicious_detection = self.config.enable_penetration_detection;
            self.route_configs.insert(route_id.to_owned(), config);
            self.revision += 1;
        }
        self.route_configs
            .get_mut(route_id)
            .expect("the route was just ensured")
    }

    const fn bump(&mut self) {
        self.revision += 1;
    }

    /// The reference's revision granularity: every attribute assignment
    /// on an initialized `RouteConfig` bumps (the pydantic-free
    /// `__setattr__` hook), and every mutation through a tracked
    /// container (`custom_validators`, `require_referrer`,
    /// `allowed_content_types`, `blocked_user_agents`, `required_headers`,
    /// `time_restrictions`, `geo_rate_limits`, `block_cloud_providers`)
    /// bumps. Plain-list appends (`behavior_rules`, `ip_*` after
    /// assignment) and the plain `bypassed_checks` set do not.
    const fn bump_n(&mut self, times: usize) {
        self.revision += times as u64;
    }

    /// `@require_ip`: the route's IP allow/deny lists (entries that are
    /// set replace; `None`/empty leaves the side untouched).
    pub fn require_ip(
        &mut self,
        route_id: &str,
        whitelist: Option<Vec<String>>,
        blacklist: Option<Vec<String>>,
    ) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        let mut assignments = 0;
        if let Some(whitelist) = whitelist
            && !whitelist.is_empty()
        {
            route.ip_whitelist = Some(whitelist);
            assignments += 1;
        }
        if let Some(blacklist) = blacklist
            && !blacklist.is_empty()
        {
            route.ip_blacklist = Some(blacklist);
            assignments += 1;
        }
        self.bump_n(assignments);
        self
    }

    /// `@block_countries`: uppercased (the reference normalizes).
    pub fn block_countries(&mut self, route_id: &str, countries: &[&str]) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        route.blocked_countries = Some(
            countries
                .iter()
                .map(|country| country.to_ascii_uppercase())
                .collect(),
        );
        self.bump();
        self
    }

    /// `@allow_countries`: uppercased (the reference normalizes).
    pub fn allow_countries(&mut self, route_id: &str, countries: &[&str]) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        route.whitelist_countries = Some(
            countries
                .iter()
                .map(|country| country.to_ascii_uppercase())
                .collect(),
        );
        self.bump();
        self
    }

    /// `@block_clouds`: no providers blocks every
    /// [`VALID_CLOUD_PROVIDERS`] entry; named entries outside the
    /// reference set are ignored (the reference logs them) and returned
    /// here, sorted.
    pub fn block_clouds(&mut self, route_id: &str, providers: Option<Vec<String>>) -> Vec<String> {
        let route = self.ensure_route_config(route_id);
        let ignored = match providers {
            None => {
                route.block_cloud_providers = VALID_CLOUD_PROVIDERS
                    .iter()
                    .map(|&p| p.to_owned())
                    .collect();
                BTreeSet::new()
            }
            Some(providers) => {
                let mut ignored: BTreeSet<String> = BTreeSet::new();
                let valid: BTreeSet<String> = providers
                    .into_iter()
                    .filter(|provider| {
                        let base = provider
                            .split_once(":!")
                            .map_or(provider.as_str(), |(base, _)| base);
                        let known = VALID_CLOUD_PROVIDERS.contains(&base);
                        if !known {
                            ignored.insert(provider.clone());
                        }
                        known
                    })
                    .collect();
                route.block_cloud_providers = valid;
                ignored
            }
        };
        self.bump();
        ignored.into_iter().collect()
    }

    /// `@bypass`: unions the names the reference
    /// [`VALID_BYPASS_CHECKS`] set knows into the route's
    /// `bypassed_checks`; unknown names are ignored (the reference logs
    /// them) and returned here, sorted.
    pub fn bypass(&mut self, route_id: &str, checks: &[&str]) -> Vec<String> {
        let route = self.ensure_route_config(route_id);
        let mut ignored: BTreeSet<String> = BTreeSet::new();
        for check in checks {
            if VALID_BYPASS_CHECKS.contains(check) {
                route.bypassed_checks.insert((*check).to_owned());
            } else {
                ignored.insert((*check).to_owned());
            }
        }
        ignored.into_iter().collect()
    }

    /// `@time_window`: the route's access window
    /// (`start`/`end`/`timezone`, the reference dict shape).
    pub fn time_window(
        &mut self,
        route_id: &str,
        start_time: &str,
        end_time: &str,
        timezone: &str,
    ) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        route.time_restrictions = Some(BTreeMap::from([
            (String::from("start"), start_time.to_owned()),
            (String::from("end"), end_time.to_owned()),
            (String::from("timezone"), timezone.to_owned()),
        ]));
        self.bump();
        self
    }

    /// `@suspicious_detection`: the route's penetration-detection toggle.
    pub fn suspicious_detection(&mut self, route_id: &str, enabled: bool) -> &mut Self {
        self.ensure_route_config(route_id)
            .enable_suspicious_detection = enabled;
        self.bump();
        self
    }

    /// `@honeypot_detection`: registers the reference's honeypot
    /// validator over the trap fields - a filled trap field in the
    /// form-encoded or JSON body answers `403 "Forbidden"`; the check
    /// applies to POST/PUT/PATCH requests with a buffered body only.
    pub fn honeypot_detection(&mut self, route_id: &str, trap_fields: &[&str]) -> &mut Self {
        let traps: Vec<String> = trap_fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect();
        let validator: CustomValidatorFn =
            Arc::new(move |context: &CustomRequestContext<'_>| honeypot_validator(&traps, context));
        self.ensure_route_config(route_id)
            .custom_validators
            .push(validator);
        self.bump();
        self
    }

    /// `@require_https`.
    pub fn require_https(&mut self, route_id: &str) -> &mut Self {
        self.ensure_route_config(route_id).require_https = true;
        self.bump();
        self
    }

    /// `@require_auth`: the route's authentication scheme and verifier.
    ///
    /// # Errors
    ///
    /// [`DecoratorError`] when the route already carries the
    /// presence-only `require_authorization_header` (the reference's
    /// mutually-exclusive combination).
    pub fn require_auth(
        &mut self,
        route_id: &str,
        auth_type: &str,
        verifier: Option<AuthVerifier>,
    ) -> Result<&mut Self, DecoratorError> {
        let route = self.ensure_route_config(route_id);
        if route.authorization_header_required.is_some() {
            return Err(conflict(
                "require_auth cannot be combined with require_authorization_header; the latter is presence-only and mutually exclusive with authenticated routes",
            ));
        }
        route.auth_required = Some(auth_type.to_owned());
        route.auth_verifier = verifier;
        self.bump_n(2);
        Ok(self)
    }

    /// `@api_key_auth`: the route's API-key header and verifier (the
    /// header lands in `required_headers` with the reference's
    /// `"required"` sentinel).
    ///
    /// # Errors
    ///
    /// [`DecoratorError`] on the
    /// `require_authorization_header` conflict.
    pub fn api_key_auth(
        &mut self,
        route_id: &str,
        header_name: &str,
        verifier: Option<AuthVerifier>,
    ) -> Result<&mut Self, DecoratorError> {
        let route = self.ensure_route_config(route_id);
        if route.authorization_header_required.is_some() {
            return Err(conflict(
                "api_key_auth cannot be combined with require_authorization_header; the latter is presence-only and mutually exclusive with authenticated routes",
            ));
        }
        route.api_key_required = true;
        route
            .required_headers
            .insert(header_name.to_owned(), String::from("required"));
        route.api_key_header = Some(header_name.to_owned());
        route.api_key_verifier = verifier;
        self.bump_n(4);
        Ok(self)
    }

    /// `@require_authorization_header`: presence-only.
    ///
    /// # Errors
    ///
    /// [`DecoratorError`] on the
    /// `require_auth`/`api_key_auth` conflict.
    pub fn require_authorization_header(
        &mut self,
        route_id: &str,
        scheme: &str,
    ) -> Result<&mut Self, DecoratorError> {
        let route = self.ensure_route_config(route_id);
        if route.auth_required.is_some() || route.api_key_required {
            return Err(conflict(
                "require_authorization_header cannot be combined with require_auth or api_key_auth; it is presence-only and mutually exclusive with authenticated routes",
            ));
        }
        route.authorization_header_required = Some(scheme.to_owned());
        self.bump();
        Ok(self)
    }

    /// `@require_headers`: the route's required header pairs (merged).
    pub fn require_headers(
        &mut self,
        route_id: &str,
        headers: BTreeMap<String, String>,
    ) -> &mut Self {
        self.ensure_route_config(route_id)
            .required_headers
            .extend(headers);
        self.bump();
        self
    }

    /// `@block_user_agents`: extends the route's blocked patterns.
    pub fn block_user_agents(&mut self, route_id: &str, patterns: &[&str]) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        route
            .blocked_user_agents
            .extend(patterns.iter().map(|pattern| (*pattern).to_owned()));
        self.bump();
        self
    }

    /// `@usage_monitor`: a `usage` behavior rule
    /// (`threshold = max_calls`).
    pub fn usage_monitor(
        &mut self,
        route_id: &str,
        max_calls: u32,
        window: u64,
        action: &str,
    ) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        route.behavior_rules.push(BehaviorRule {
            rule_type: String::from("usage"),
            threshold: max_calls,
            window,
            pattern: String::new(),
            action: action.to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        });
        self
    }

    /// `@return_monitor`: a `return_pattern` behavior rule.
    ///
    /// # Errors
    ///
    /// [`DecoratorError`] when the pattern does not compile (the
    /// reference `_validate_return_pattern_body_scan`).
    pub fn return_monitor(
        &mut self,
        route_id: &str,
        pattern: &str,
        max_occurrences: u32,
        window: u64,
        action: &str,
    ) -> Result<&mut Self, DecoratorError> {
        validate_return_pattern(pattern)?;
        let route = self.ensure_route_config(route_id);
        route.behavior_rules.push(BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: max_occurrences,
            window,
            pattern: pattern.to_owned(),
            action: action.to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        });
        Ok(self)
    }

    /// `@behavior_analysis`: extends the route's behavior rules,
    /// validating every `return_pattern` rule's pattern.
    ///
    /// # Errors
    ///
    /// [`DecoratorError`] when a `return_pattern` rule carries a
    /// pattern that does not compile.
    pub fn behavior_analysis(
        &mut self,
        route_id: &str,
        rules: Vec<BehaviorRule>,
    ) -> Result<&mut Self, DecoratorError> {
        for rule in &rules {
            if rule.rule_type == "return_pattern" && !rule.pattern.is_empty() {
                validate_return_pattern(&rule.pattern)?;
            }
        }
        let route = self.ensure_route_config(route_id);
        route.behavior_rules.extend(rules);
        Ok(self)
    }

    /// `@suspicious_frequency`: a `frequency` behavior rule
    /// (`threshold = max_frequency * window`, the reference's
    /// `int()` truncation).
    pub fn suspicious_frequency(
        &mut self,
        route_id: &str,
        max_frequency: f64,
        window: u64,
        action: &str,
    ) -> &mut Self {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        // the reference's int() truncation has the same behavior
        let max_calls = (max_frequency * window as f64) as u32;
        let route = self.ensure_route_config(route_id);
        route.behavior_rules.push(BehaviorRule {
            rule_type: String::from("frequency"),
            threshold: max_calls,
            window,
            pattern: String::new(),
            action: action.to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        });
        self
    }

    /// `@content_type_filter`: the route's allowed content types.
    pub fn content_type_filter(&mut self, route_id: &str, allowed_types: &[&str]) -> &mut Self {
        self.ensure_route_config(route_id).allowed_content_types =
            Some(allowed_types.iter().map(|ty| (*ty).to_owned()).collect());
        self.bump();
        self
    }

    /// `@max_request_size`: the route's body cap, in bytes.
    pub fn max_request_size(&mut self, route_id: &str, size_bytes: u64) -> &mut Self {
        self.ensure_route_config(route_id).max_request_size = Some(size_bytes);
        self.bump();
        self
    }

    /// `@require_referrer`: the route's allowed referrer domains.
    pub fn require_referrer(&mut self, route_id: &str, allowed_domains: &[&str]) -> &mut Self {
        self.ensure_route_config(route_id).require_referrer = Some(
            allowed_domains
                .iter()
                .map(|domain| (*domain).to_owned())
                .collect(),
        );
        self.bump();
        self
    }

    /// `@custom_validation`: appends the route's validator.
    pub fn custom_validation(&mut self, route_id: &str, validator: CustomValidatorFn) -> &mut Self {
        self.ensure_route_config(route_id)
            .custom_validators
            .push(validator);
        self.bump();
        self
    }

    /// `@detection_exclusion`: the route's five detection knobs; every
    /// `None` leaves that knob untouched.
    pub fn detection_exclusion(
        &mut self,
        route_id: &str,
        headers: Option<BTreeSet<String>>,
        params: Option<BTreeSet<String>>,
        body_fields: Option<BTreeSet<String>>,
        categories: Option<BTreeSet<String>>,
        scan_body: Option<bool>,
    ) -> &mut Self {
        let present = [
            headers.is_some(),
            params.is_some(),
            body_fields.is_some(),
            categories.is_some(),
            scan_body.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        let route = self.ensure_route_config(route_id);
        if let Some(headers) = headers {
            route.excluded_detection_headers = Some(headers);
        }
        if let Some(params) = params {
            route.excluded_detection_params = Some(params);
        }
        if let Some(body_fields) = body_fields {
            route.excluded_detection_body_fields = Some(body_fields);
        }
        if let Some(categories) = categories {
            route.enabled_detection_categories = Some(categories);
        }
        if let Some(scan_body) = scan_body {
            route.detection_scan_body = Some(scan_body);
        }
        self.bump_n(present);
        self
    }

    /// `@rate_limit`: the route's request count and window.
    pub fn rate_limit(&mut self, route_id: &str, requests: u32, window: u64) -> &mut Self {
        let route = self.ensure_route_config(route_id);
        route.rate_limit = Some(requests);
        route.rate_limit_window = Some(window);
        self.bump_n(2);
        self
    }

    /// `@geo_rate_limit`: the route's per-country limits.
    pub fn geo_rate_limit(
        &mut self,
        route_id: &str,
        limits: BTreeMap<String, (u32, u64)>,
    ) -> &mut Self {
        self.ensure_route_config(route_id).geo_rate_limits = Some(limits);
        self.bump();
        self
    }
}

/// The reference `_validate_return_pattern_body_scan`'s compile half: the
/// pattern must compile under the engine's compiler (the body-scan
/// constraints are the config's scan ceilings, which the scanner applies
/// at run time).
fn validate_return_pattern(pattern: &str) -> Result<(), DecoratorError> {
    crate::compiler::compile(pattern).map_err(|error| DecoratorError {
        message: format!("return_pattern does not compile ({error})"),
    })?;
    Ok(())
}

/// `urllib.parse.unquote_plus` for one component: `%XX` runs and `+`
/// (form-encoding's space) decode; malformed escapes stay literal.
fn percent_decode(component: &str) -> String {
    let plus_decoded = component.replace('+', " ");
    let bytes = plus_decoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            )
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The reference `honeypot_detection` validator: POST/PUT/PATCH only, the
/// trap fields probed in the form-encoded and JSON bodies, a filled trap
/// answers `403 "Forbidden"`.
fn honeypot_validator(
    trap_fields: &[String],
    context: &CustomRequestContext<'_>,
) -> Option<ValidatorAnswer> {
    if context.method != "POST" && context.method != "PUT" && context.method != "PATCH" {
        return None;
    }
    let body = context.body?;
    let filled = |data: &BTreeMap<String, String>| {
        trap_fields
            .iter()
            .any(|field| data.get(field).is_some_and(|value| !value.is_empty()))
    };

    // The form view: `parse_qsl`-decoded first-value pairs.
    let mut form: BTreeMap<String, String> = BTreeMap::new();
    for pair in body.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        form.entry(percent_decode(name))
            .or_insert_with(|| percent_decode(value));
    }
    if filled(&form) {
        return Some(ValidatorAnswer::Response(
            crate::custom_checks::CustomResponse {
                status: Some(403),
                body: Some(String::from("Forbidden")),
            },
        ));
    }

    // The JSON view: top-level string fields (unparsable JSON skips, the
    // reference logs and moves on).
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(object) = value.as_object()
    {
        let json_fields: BTreeMap<String, String> = object
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
            .collect();
        if filled(&json_fields) {
            return Some(ValidatorAnswer::Response(
                crate::custom_checks::CustomResponse {
                    status: Some(403),
                    body: Some(String::from("Forbidden")),
                },
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_config::SecurityConfig;

    /// A fresh decorator over the reference-default config.
    fn decorator() -> SecurityDecorator {
        SecurityDecorator::new(SecurityConfig::default())
    }

    #[test]
    fn first_touch_seeds_the_reference_default_and_bumps_the_revision() {
        let mut decorator = decorator();
        assert_eq!(decorator.route_config_revision(), 0);
        let config = decorator.ensure_route_config("GET /login");
        assert!(
            config.enable_suspicious_detection,
            "the config's enable_penetration_detection default is true"
        );

        let mut decorator = SecurityDecorator::new(SecurityConfig {
            enable_penetration_detection: false,
            ..SecurityConfig::default()
        });
        let config = decorator.ensure_route_config("GET /login");
        assert!(!config.enable_suspicious_detection);
    }

    #[test]
    fn ensure_is_idempotent_per_route() {
        let mut decorator = decorator();
        decorator.ensure_route_config("GET /login").rate_limit = Some(5);
        let again = decorator.ensure_route_config("GET /login");
        assert_eq!(again.rate_limit, Some(5));
        assert!(decorator.get_route_config("GET /signup").is_none());
        assert!(decorator.route_ids().eq(["GET /login"]));
    }

    #[test]
    fn require_ip_sets_both_sides_and_ignores_empties() {
        let mut decorator = decorator();
        decorator.require_ip(
            "GET /login",
            Some(vec![String::from("10.0.0.0/8")]),
            Some(vec![String::from("203.0.113.9")]),
        );
        let route = decorator.get_route_config("GET /login").expect("route");
        assert_eq!(
            route.ip_whitelist.as_deref(),
            Some([String::from("10.0.0.0/8")].as_slice())
        );
        assert_eq!(
            route.ip_blacklist.as_deref(),
            Some([String::from("203.0.113.9")].as_slice())
        );

        decorator.require_ip("GET /signup", None, Some(Vec::new()));
        let route = decorator.get_route_config("GET /signup").expect("route");
        assert_eq!(route.ip_whitelist, None);
        assert_eq!(route.ip_blacklist, None);
    }

    #[test]
    fn country_decorators_uppercase() {
        let mut decorator = decorator();
        decorator
            .block_countries("GET /eu", &["br", "de"])
            .allow_countries("GET /eu", &["us"]);
        let route = decorator.get_route_config("GET /eu").expect("route");
        assert_eq!(
            route.blocked_countries.as_deref(),
            Some([String::from("BR"), String::from("DE")].as_slice())
        );
        assert_eq!(
            route.whitelist_countries.as_deref(),
            Some([String::from("US")].as_slice())
        );
    }

    #[test]
    fn block_clouds_blocks_everything_or_filters_unknowns() {
        let mut decorator = decorator();
        let ignored = decorator.block_clouds("GET /api", None);
        assert!(ignored.is_empty());
        let route = decorator.get_route_config("GET /api").expect("route");
        assert_eq!(
            route.block_cloud_providers.len(),
            VALID_CLOUD_PROVIDERS.len()
        );

        let ignored = decorator.block_clouds(
            "GET /api2",
            Some(vec![
                String::from("AWS"),
                String::from("NotACloud"),
                String::from("AWS:!prod"),
            ]),
        );
        assert_eq!(ignored, [String::from("NotACloud")]);
        let route = decorator.get_route_config("GET /api2").expect("route");
        // The reference keeps the provider strings verbatim (the
        // region-scoped `AWS:!prod` form rides along with its base).
        assert!(route.block_cloud_providers.contains("AWS"));
        assert!(route.block_cloud_providers.contains("AWS:!prod"));
        assert_eq!(route.block_cloud_providers.len(), 2);
    }

    #[test]
    fn bypass_keeps_only_the_reference_names_and_unions() {
        let mut decorator = decorator();
        let ignored =
            decorator.bypass("GET /internal", &["ip", "rate_limit", "all", "not_a_check"]);
        assert_eq!(ignored, [String::from("not_a_check")]);
        let ignored2 = decorator.bypass("GET /internal", &["ip_ban", "mystery"]);
        assert_eq!(ignored2, [String::from("mystery")]);
        let route = decorator.get_route_config("GET /internal").expect("route");
        assert!(route.bypassed_checks.contains("all"));
        assert!(route.bypassed_checks.contains("ip"));
        assert!(route.bypassed_checks.contains("ip_ban"));
        assert!(route.bypassed_checks.contains("rate_limit"));
    }

    #[test]
    fn the_bypass_vocabulary_is_the_reference_set() {
        assert_eq!(
            VALID_BYPASS_CHECKS,
            ["all", "ip_ban", "ip", "clouds", "rate_limit", "penetration"]
        );
        assert_eq!(
            VALID_CLOUD_PROVIDERS,
            ["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"]
        );
    }

    #[test]
    fn time_window_and_suspicious_detection_set_their_knobs() {
        let mut decorator = decorator();
        decorator
            .time_window("GET /night", "22:00", "06:00", "UTC")
            .suspicious_detection("GET /night", false);
        let route = decorator.get_route_config("GET /night").expect("route");
        let restrictions = route.time_restrictions.as_ref().expect("restrictions");
        assert_eq!(restrictions.get("start").map(String::as_str), Some("22:00"));
        assert_eq!(restrictions.get("end").map(String::as_str), Some("06:00"));
        assert_eq!(
            restrictions.get("timezone").map(String::as_str),
            Some("UTC")
        );
        assert!(!route.enable_suspicious_detection);
    }

    #[test]
    fn the_honeypot_validator_answers_403_on_a_filled_trap() {
        let mut decorator = decorator();
        decorator.honeypot_detection("POST /form", &["website", "bot_field"]);
        let route = decorator.get_route_config("POST /form").expect("route");
        assert_eq!(route.custom_validators.len(), 1);
        let validator = route.custom_validators[0].clone();

        // A POST with a filled trap in the form body: 403 Forbidden.
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some("name=renn&website=https://spam.example"),
        };
        assert_eq!(
            validator(&context),
            Some(ValidatorAnswer::Response(CustomResponse {
                status: Some(403),
                body: Some(String::from("Forbidden")),
            }))
        );

        // An empty trap: allowed. A percent-encoded trap value decodes
        // before the emptiness check (the reference's parse_qsl view).
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some("name=renn&website="),
        };
        assert!(validator(&context).is_none());
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some("website=https%3A%2F%2Fspam.example&name=renn"),
        };
        assert_eq!(
            validator(&context),
            Some(ValidatorAnswer::Response(CustomResponse {
                status: Some(403),
                body: Some(String::from("Forbidden")),
            }))
        );
        // A malformed escape stays literal: `%zz` reads as the literal
        // three characters, which fills the trap (a filled value either
        // way - the decode path itself is what the case pins).
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some("website=%zz&name=renn"),
        };
        assert!(validator(&context).is_some());

        // A filled trap in JSON: 403.
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some(r#"{"name":"renn","bot_field":"gotcha"}"#),
        };
        assert!(validator(&context).is_some());

        // An all-empty JSON trap set: allowed (the filled() false arm of
        // the JSON view).
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some(r#"{"name":"renn","bot_field":""}"#),
        };
        assert!(validator(&context).is_none());

        // Unparsable JSON skips (the reference logs and moves on).
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: Some("not json"),
        };
        assert!(validator(&context).is_none());

        // GET never probes.
        let context = CustomRequestContext {
            method: "GET",
            path: "/form",
            client_ip: None,
            body: Some("website=x"),
        };
        assert!(validator(&context).is_none());

        // No body (the fairing lane): nothing to probe.
        let context = CustomRequestContext {
            method: "POST",
            path: "/form",
            client_ip: None,
            body: None,
        };
        assert!(validator(&context).is_none());
    }

    #[test]
    fn the_auth_trio_enforces_the_reference_mutual_exclusions() {
        let mut first = decorator();
        first
            .require_auth("GET /private", "bearer", None)
            .expect("no conflict");
        let error = first
            .require_authorization_header("GET /private", "bearer")
            .unwrap_err();
        assert!(
            error
                .message
                .contains("require_authorization_header cannot be combined with require_auth"),
            "{error}"
        );

        let mut second = decorator();
        second
            .require_authorization_header("GET /public", "basic")
            .expect("no conflict");
        let error = second
            .api_key_auth("GET /public", "X-API-Key", None)
            .unwrap_err();
        assert!(
            error
                .message
                .contains("api_key_auth cannot be combined with require_authorization_header"),
            "{error}"
        );
        let error = second
            .require_auth("GET /public", "bearer", None)
            .unwrap_err();
        assert!(
            error
                .message
                .contains("require_auth cannot be combined with require_authorization_header"),
            "{error}"
        );
    }

    #[test]
    fn api_key_auth_sets_the_reference_fields() {
        let mut decorator = decorator();
        decorator
            .api_key_auth("GET /partner", "X-API-Key", None)
            .expect("no conflict");
        let route = decorator.get_route_config("GET /partner").expect("route");
        assert!(route.api_key_required);
        assert_eq!(
            route.required_headers.get("X-API-Key").map(String::as_str),
            Some("required")
        );
        assert_eq!(route.api_key_header.as_deref(), Some("X-API-Key"));
    }

    #[test]
    fn require_headers_merges_and_require_https_flags() {
        let mut decorator = decorator();
        decorator
            .require_https("GET /strict")
            .require_headers(
                "GET /strict",
                BTreeMap::from([(String::from("x-tenant"), String::from("required"))]),
            )
            .require_headers(
                "GET /strict",
                BTreeMap::from([(String::from("x-region"), String::from("eu"))]),
            );
        let route = decorator.get_route_config("GET /strict").expect("route");
        assert!(route.require_https);
        assert_eq!(route.required_headers.len(), 2);
    }

    #[test]
    fn the_behavioral_factories_build_the_reference_rules() {
        let mut decorator = decorator();
        decorator
            .usage_monitor("GET /quota", 100, 3600, "ban")
            .suspicious_frequency("GET /quota", 0.5, 300, "alert");
        let route = decorator.get_route_config("GET /quota").expect("route");
        assert_eq!(route.behavior_rules.len(), 2);
        assert_eq!(route.behavior_rules[0].rule_type, "usage");
        assert_eq!(route.behavior_rules[0].threshold, 100);
        assert_eq!(route.behavior_rules[1].rule_type, "frequency");
        // int(0.5 * 300) = 150.
        assert_eq!(route.behavior_rules[1].threshold, 150);

        decorator
            .return_monitor("GET /quota", "status:500", 3, 86_400, "ban")
            .expect("compilable pattern");
        let route = decorator.get_route_config("GET /quota").expect("route");
        assert_eq!(route.behavior_rules.len(), 3);
        assert_eq!(route.behavior_rules[2].rule_type, "return_pattern");

        let error = decorator
            .return_monitor("GET /quota", "([", 3, 60, "ban")
            .unwrap_err();
        assert!(error.message.contains("does not compile"), "{error}");

        let rules = vec![BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: 2,
            window: 60,
            pattern: String::from("(["),
            action: String::from("ban"),
            ban_duration: None,
            correlate_with_detection: false,
        }];
        let error = decorator
            .behavior_analysis("GET /quota", rules)
            .unwrap_err();
        assert!(error.message.contains("does not compile"), "{error}");

        let rules = vec![BehaviorRule {
            rule_type: String::from("usage"),
            threshold: 5,
            window: 60,
            pattern: String::new(),
            action: String::from("log"),
            ban_duration: None,
            correlate_with_detection: false,
        }];
        decorator
            .behavior_analysis("GET /quota", rules)
            .expect("usage rules carry no pattern");
        let route = decorator.get_route_config("GET /quota").expect("route");
        assert_eq!(route.behavior_rules.len(), 4);
    }

    #[test]
    fn the_content_filtering_factories_set_their_knobs() {
        let mut decorator = decorator();
        decorator
            .block_user_agents("POST /upload", &["sqlmap", "havij"])
            .content_type_filter("POST /upload", &["application/json"])
            .max_request_size("POST /upload", 1_048_576)
            .require_referrer("POST /upload", &["https://app.test"]);
        let route = decorator.get_route_config("POST /upload").expect("route");
        assert_eq!(route.blocked_user_agents, ["sqlmap", "havij"]);
        assert_eq!(
            route.allowed_content_types.as_deref(),
            Some([String::from("application/json")].as_slice())
        );
        assert_eq!(route.max_request_size, Some(1_048_576));
        assert_eq!(
            route.require_referrer.as_deref(),
            Some([String::from("https://app.test")].as_slice())
        );
    }

    #[test]
    fn detection_exclusion_sets_only_the_present_knobs() {
        let mut decorator = decorator();
        decorator.detection_exclusion(
            "POST /scan-me",
            Some(BTreeSet::from([String::from("x-api-key")])),
            None,
            None,
            Some(BTreeSet::from([String::from("xss")])),
            Some(false),
        );
        let route = decorator.get_route_config("POST /scan-me").expect("route");
        assert_eq!(
            route.excluded_detection_headers,
            Some(BTreeSet::from([String::from("x-api-key")]))
        );
        assert_eq!(route.excluded_detection_params, None);
        assert_eq!(route.excluded_detection_body_fields, None);
        assert_eq!(
            route.enabled_detection_categories,
            Some(BTreeSet::from([String::from("xss")]))
        );
        assert_eq!(route.detection_scan_body, Some(false));
    }

    #[test]
    fn the_rate_limiting_factories_set_their_tiers() {
        let mut decorator = decorator();
        decorator.rate_limit("POST /login", 5, 60).geo_rate_limit(
            "POST /login",
            BTreeMap::from([(String::from("BR"), (10, 30))]),
        );
        let route = decorator.get_route_config("POST /login").expect("route");
        assert_eq!(route.rate_limit, Some(5));
        assert_eq!(route.rate_limit_window, Some(60));
        let limits = route.geo_rate_limits.as_ref().expect("limits");
        assert_eq!(limits.get("BR"), Some(&(10, 30)));

        // The carrier's own bridge: the tier view validates and hands the
        // engine's RouteRateLimits.
        assert!(route.rate_limits().expect("valid tier").is_some());
    }

    #[test]
    fn custom_validation_appends_the_validator() {
        let mut decorator = decorator();
        let validator: CustomValidatorFn = Arc::new(|_context: &CustomRequestContext<'_>| None);
        decorator.custom_validation("GET /checked", validator);
        let route = decorator.get_route_config("GET /checked").expect("route");
        assert_eq!(route.custom_validators.len(), 1);
    }

    #[test]
    fn detection_exclusion_sets_the_params_and_body_field_knobs() {
        let mut decorator = decorator();
        decorator.detection_exclusion(
            "POST /scan-me",
            None,
            Some(BTreeSet::from([String::from("token")])),
            Some(BTreeSet::from([String::from("password")])),
            None,
            None,
        );
        let route = decorator.get_route_config("POST /scan-me").expect("route");
        assert_eq!(
            route.excluded_detection_params,
            Some(BTreeSet::from([String::from("token")]))
        );
        assert_eq!(
            route.excluded_detection_body_fields,
            Some(BTreeSet::from([String::from("password")]))
        );
    }

    #[test]
    fn the_error_display_and_the_decorator_debug_render() {
        let error = conflict("test message");
        assert_eq!(error.to_string(), "test message");
        assert!(std::error::Error::source(&error).is_none());

        let mut decorator = decorator();
        decorator.rate_limit("GET /login", 5, 60);
        let rendered = format!("{decorator:?}");
        assert!(rendered.starts_with("SecurityDecorator"), "{rendered}");
        assert!(rendered.contains("routes: 1"), "{rendered}");
        assert!(rendered.contains("revision: "), "{rendered}");
    }

    #[test]
    fn every_mutation_bumps_the_revision() {
        let mut decorator = decorator();
        let before = decorator.route_config_revision();
        decorator.rate_limit("GET /login", 5, 60);
        decorator.require_https("GET /login");
        // The reference's `bypassed_checks` is a plain set (untracked):
        // the union does not bump the revision.
        decorator.bypass("GET /login", &["ip"]);
        let after = decorator.route_config_revision();
        // Creation (1) + the two `rate_limit` assignments (2) + the
        // `require_https` assignment (1).
        assert_eq!(after - before, 4);
    }
}
