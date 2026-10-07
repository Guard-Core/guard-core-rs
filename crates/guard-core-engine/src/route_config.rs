//! The per-route configuration carrier: the reference `RouteConfig`
//! (`guard_core/decorators/route_config.py`).
//!
//! The 30 knobs the `@route_config` decorator accepts, as an
//! engine-owned struct plus the resolution seam the adapters attach per
//! route. Every knob is `None`/empty/false unless the route sets it: the
//! route-level value overrides the global `SecurityConfig` value for that
//! route only (the reference `RouteConfigResolver` semantics - the global
//! config is the fallback, the route config the override).
//!
//! The two carriers the engine already had - [`crate::rate_limit::
//! RouteRateLimits`] and [`crate::detection_exclusions::
//! RouteDetectionExclusions`] - are the views of this struct's rate-limit
//! and detection groups; the bridge methods hand them out so the existing
//! resolver seams consume one carrier.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_engine::route_config::{RouteConfig, RouteConfigResolver};
//!
//! let resolver: RouteConfigResolver = Arc::new(|method, path| {
//!     (method == "POST" && path == "/login").then(|| {
//!         Arc::new(RouteConfig {
//!             rate_limit: Some(5),
//!             require_https: true,
//!             ..RouteConfig::default()
//!         })
//!     })
//! });
//! let config = resolver("POST", "/login").expect("route config");
//! assert_eq!(config.rate_limit, Some(5));
//! assert!(resolver("GET", "/login").is_none());
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use crate::behavior::BehaviorRule;
use crate::custom_checks::CustomValidatorFn;
use crate::detection_exclusions::RouteDetectionExclusions;
use crate::headers_auth::AuthVerifier;
use crate::rate_limit::RouteRateLimits;

/// The per-route configuration carrier (the reference `RouteConfig`'s 30
/// knobs). `None`/empty inherits the global config for that knob.
#[derive(Clone)]
pub struct RouteConfig {
    /// `rate_limit`: the route's request count per window.
    pub rate_limit: Option<u32>,
    /// `rate_limit_window`: the route's window (seconds).
    pub rate_limit_window: Option<u64>,
    /// `ip_whitelist`: the route's allow list.
    pub ip_whitelist: Option<Vec<String>>,
    /// `ip_blacklist`: the route's deny list.
    pub ip_blacklist: Option<Vec<String>>,
    /// `blocked_countries`.
    pub blocked_countries: Option<Vec<String>>,
    /// `whitelist_countries`.
    pub whitelist_countries: Option<Vec<String>>,
    /// `bypassed_checks`: the check names this route skips.
    pub bypassed_checks: BTreeSet<String>,
    /// `require_https`.
    pub require_https: bool,
    /// `auth_required`: the authentication scheme the route demands.
    pub auth_required: Option<String>,
    /// `custom_validators`: the route's validator functions.
    pub custom_validators: Vec<CustomValidatorFn>,
    /// `blocked_user_agents`.
    pub blocked_user_agents: Vec<String>,
    /// `required_headers`: header name to exact value.
    pub required_headers: BTreeMap<String, String>,
    /// `behavior_rules`: the route's behavior rules.
    pub behavior_rules: Vec<BehaviorRule>,
    /// `block_cloud_providers`.
    pub block_cloud_providers: BTreeSet<String>,
    /// `max_request_size` (bytes).
    pub max_request_size: Option<u64>,
    /// `allowed_content_types`.
    pub allowed_content_types: Option<Vec<String>>,
    /// `time_restrictions`.
    pub time_restrictions: Option<BTreeMap<String, String>>,
    /// `enable_suspicious_detection` (the reference default `True`).
    pub enable_suspicious_detection: bool,
    /// `require_referrer`.
    pub require_referrer: Option<Vec<String>>,
    /// `api_key_required`.
    pub api_key_required: bool,
    /// `auth_verifier`: the route's authentication verifier.
    pub auth_verifier: Option<AuthVerifier>,
    /// `api_key_verifier`: the route's API-key verifier.
    pub api_key_verifier: Option<AuthVerifier>,
    /// `api_key_header`.
    pub api_key_header: Option<String>,
    /// `authorization_header_required`.
    pub authorization_header_required: Option<String>,
    /// `geo_rate_limits`: country code to (count, window seconds).
    pub geo_rate_limits: Option<BTreeMap<String, (u32, u64)>>,
    /// `excluded_detection_headers`.
    pub excluded_detection_headers: Option<BTreeSet<String>>,
    /// `excluded_detection_params`.
    pub excluded_detection_params: Option<BTreeSet<String>>,
    /// `excluded_detection_body_fields`.
    pub excluded_detection_body_fields: Option<BTreeSet<String>>,
    /// `enabled_detection_categories`.
    pub enabled_detection_categories: Option<BTreeSet<String>>,
    /// `detection_scan_body`.
    pub detection_scan_body: Option<bool>,
}

impl Default for RouteConfig {
    /// The reference defaults: every override `None`/empty, the two
    /// explicit booleans at their reference values.
    fn default() -> Self {
        Self {
            rate_limit: None,
            rate_limit_window: None,
            ip_whitelist: None,
            ip_blacklist: None,
            blocked_countries: None,
            whitelist_countries: None,
            bypassed_checks: BTreeSet::new(),
            require_https: false,
            auth_required: None,
            custom_validators: Vec::new(),
            blocked_user_agents: Vec::new(),
            required_headers: BTreeMap::new(),
            behavior_rules: Vec::new(),
            block_cloud_providers: BTreeSet::new(),
            max_request_size: None,
            allowed_content_types: None,
            time_restrictions: None,
            enable_suspicious_detection: true,
            require_referrer: None,
            api_key_required: false,
            auth_verifier: None,
            api_key_verifier: None,
            api_key_header: None,
            authorization_header_required: None,
            geo_rate_limits: None,
            excluded_detection_headers: None,
            excluded_detection_params: None,
            excluded_detection_body_fields: None,
            enabled_detection_categories: None,
            detection_scan_body: None,
        }
    }
}

impl RouteConfig {
    /// The rate-limit view (`rate_limit` + `rate_limit_window` +
    /// `geo_rate_limits`): the carrier the engine's route-rate resolver
    /// seam consumes, `None` when
    /// the route sets no rate-limit override. `Err` on a zero limit or
    /// window (the engine's validated constructor).
    pub fn rate_limits(
        &self,
    ) -> Result<Option<RouteRateLimits>, crate::rate_limit::RateLimitConfigError> {
        if self.rate_limit.is_none() && self.geo_rate_limits.is_none() {
            return Ok(None);
        }
        let geo = self.geo_rate_limits.as_ref().map(|geo| {
            geo.iter()
                .map(|(country, (requests, window))| {
                    (
                        country.clone(),
                        crate::rate_limit::RateLimitEntry {
                            requests: *requests,
                            window: *window,
                        },
                    )
                })
                .collect::<HashMap<_, _>>()
        });
        RouteRateLimits::new(self.rate_limit, self.rate_limit_window, geo).map(Some)
    }

    /// The detection view (the five exclusion/enablement knobs): the
    /// carrier the [`crate::detection_exclusions`] seam consumes.
    #[must_use]
    pub fn detection_exclusions(&self) -> RouteDetectionExclusions {
        RouteDetectionExclusions {
            excluded_detection_headers: self
                .excluded_detection_headers
                .as_ref()
                .map(|set| set.iter().cloned().collect()),
            excluded_detection_params: self
                .excluded_detection_params
                .as_ref()
                .map(|set| set.iter().cloned().collect()),
            excluded_detection_body_fields: self
                .excluded_detection_body_fields
                .as_ref()
                .map(|set| set.iter().cloned().collect()),
            enabled_detection_categories: self
                .enabled_detection_categories
                .as_ref()
                .map(|set| set.iter().cloned().collect()),
            detection_scan_body: self.detection_scan_body,
        }
    }
}

/// How the adapter learns a route's config: `(method, path)` to the
/// route override.
///
/// `None` when the route carries none (the global config applies). The
/// reference `RouteConfigResolver` resolves the same tuple; the adapter's
/// router is the authority on the match.
pub type RouteConfigResolver = Arc<dyn Fn(&str, &str) -> Option<Arc<RouteConfig>> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    /// A default config with `mutate` applied (30 fields make literal
    /// initializers unreadable).
    fn with(mutate: impl FnOnce(&mut RouteConfig)) -> RouteConfig {
        let mut config = RouteConfig::default();
        mutate(&mut config);
        config
    }

    #[test]
    fn defaults_inherit_everything() {
        let config = RouteConfig::default();
        assert_eq!(config.rate_limit, None);
        assert_eq!(config.rate_limit_window, None);
        assert_eq!(config.ip_whitelist, None);
        assert_eq!(config.ip_blacklist, None);
        assert_eq!(config.blocked_countries, None);
        assert_eq!(config.whitelist_countries, None);
        assert!(config.bypassed_checks.is_empty());
        assert!(!config.require_https);
        assert_eq!(config.auth_required, None);
        assert!(config.custom_validators.is_empty());
        assert!(config.blocked_user_agents.is_empty());
        assert!(config.required_headers.is_empty());
        assert!(config.behavior_rules.is_empty());
        assert!(config.block_cloud_providers.is_empty());
        assert_eq!(config.max_request_size, None);
        assert_eq!(config.allowed_content_types, None);
        assert_eq!(config.time_restrictions, None);
        assert!(config.enable_suspicious_detection);
        assert_eq!(config.require_referrer, None);
        assert!(!config.api_key_required);
        assert!(config.auth_verifier.is_none());
        assert!(config.api_key_verifier.is_none());
        assert_eq!(config.api_key_header, None);
        assert_eq!(config.authorization_header_required, None);
        assert_eq!(config.geo_rate_limits, None);
        assert_eq!(config.excluded_detection_headers, None);
        assert_eq!(config.excluded_detection_params, None);
        assert_eq!(config.excluded_detection_body_fields, None);
        assert_eq!(config.enabled_detection_categories, None);
        assert_eq!(config.detection_scan_body, None);
    }

    #[test]
    fn the_rate_limit_view_carries_both_knobs_or_nothing() {
        let config = RouteConfig {
            rate_limit_window: Some(60),
            ..RouteConfig::default()
        };
        // A window alone never configures a tier (the reference shape).
        assert!(config.rate_limits().expect("valid").is_none());

        let config = RouteConfig {
            rate_limit: Some(5),
            rate_limit_window: Some(60),
            geo_rate_limits: Some(BTreeMap::from([(String::from("BR"), (10, 30))])),
            ..RouteConfig::default()
        };
        let limits = config
            .rate_limits()
            .expect("valid")
            .expect("tier configured");
        assert_eq!(limits.rate_limit(), Some(5));
        assert_eq!(limits.rate_limit_window(), Some(60));
        assert_eq!(
            limits.geo_rate_limits().map(std::collections::HashMap::len),
            Some(1)
        );
    }

    #[test]
    fn the_detection_view_maps_the_five_knobs() {
        let config = RouteConfig::default();
        let view = config.detection_exclusions();
        assert_eq!(view.excluded_detection_headers, None);
        assert_eq!(view.excluded_detection_params, None);
        assert_eq!(view.excluded_detection_body_fields, None);
        assert_eq!(view.enabled_detection_categories, None);
        assert_eq!(view.detection_scan_body, None);

        let config = with(|config| {
            config.excluded_detection_headers = Some(BTreeSet::from([String::from("x-api-key")]));
            config.detection_scan_body = Some(false);
        });
        let view = config.detection_exclusions();
        assert_eq!(
            view.excluded_detection_headers,
            Some(vec![String::from("x-api-key")])
        );
        assert_eq!(view.detection_scan_body, Some(false));
    }

    #[test]
    fn a_zero_route_limit_is_rejected_by_the_engine_validator() {
        let config = with(|config| config.rate_limit = Some(0));
        assert!(config.rate_limits().is_err());
    }

    #[test]
    fn the_resolver_seams_method_and_path() {
        let resolver: RouteConfigResolver = Arc::new(|method, path| {
            (method == "POST" && path == "/login").then(|| {
                Arc::new(RouteConfig {
                    rate_limit: Some(5),
                    require_https: true,
                    ..RouteConfig::default()
                })
            })
        });
        let config = resolver("POST", "/login").expect("route config");
        assert_eq!(config.rate_limit, Some(5));
        assert!(config.require_https);
        assert!(resolver("GET", "/login").is_none());
        assert!(resolver("POST", "/signup").is_none());
    }
}
