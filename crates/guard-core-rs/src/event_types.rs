//! The reference `EVENT_*` constants, byte-identical string values.
//!
//! Source: `guard_core/core/events/event_types.py`. Every emitted event
//! uses one of these values; [`EVENT_TYPE_VALUES`] is the same set the
//! reference validates `alerts` configs against.
//!
//! Names stay upper-snake to match the reference symbols one to one, the
//! same convention the Go and TypeScript ports kept.

/// `EVENT_PENETRATION_ATTEMPT`.
pub const EVENT_PENETRATION_ATTEMPT: &str = "penetration_attempt";
/// `EVENT_IP_BLOCKED`.
pub const EVENT_IP_BLOCKED: &str = "ip_blocked";
/// `EVENT_IP_BANNED`.
pub const EVENT_IP_BANNED: &str = "ip_banned";
/// `EVENT_IP_BAN_FAILED`.
pub const EVENT_IP_BAN_FAILED: &str = "ip_ban_failed";
/// `EVENT_IP_UNBANNED`.
pub const EVENT_IP_UNBANNED: &str = "ip_unbanned";
/// `EVENT_CLOUD_BLOCKED`.
pub const EVENT_CLOUD_BLOCKED: &str = "cloud_blocked";
/// `EVENT_HTTPS_ENFORCED`.
pub const EVENT_HTTPS_ENFORCED: &str = "https_enforced";
/// `EVENT_DECORATOR_VIOLATION`.
pub const EVENT_DECORATOR_VIOLATION: &str = "decorator_violation";
/// `EVENT_BEHAVIOR_VIOLATION`.
pub const EVENT_BEHAVIOR_VIOLATION: &str = "behavioral_violation";
/// `EVENT_PATTERN_DETECTED`.
pub const EVENT_PATTERN_DETECTED: &str = "pattern_detected";
/// `EVENT_DYNAMIC_RULE_UPDATED`.
pub const EVENT_DYNAMIC_RULE_UPDATED: &str = "dynamic_rule_updated";
/// `EVENT_DYNAMIC_RULE_APPLIED`.
pub const EVENT_DYNAMIC_RULE_APPLIED: &str = "dynamic_rule_applied";
/// `EVENT_DYNAMIC_RULE_VIOLATION`.
pub const EVENT_DYNAMIC_RULE_VIOLATION: &str = "dynamic_rule_violation";
/// `EVENT_EMERGENCY_MODE`.
pub const EVENT_EMERGENCY_MODE: &str = "emergency_mode_activated";
/// `EVENT_ACCESS_DENIED`.
pub const EVENT_ACCESS_DENIED: &str = "access_denied";
/// `EVENT_AUTHENTICATION_FAILED`.
pub const EVENT_AUTHENTICATION_FAILED: &str = "authentication_failed";
/// `EVENT_CONTENT_FILTERED`.
pub const EVENT_CONTENT_FILTERED: &str = "content_filtered";
/// `EVENT_COUNTRY_BLOCKED`.
pub const EVENT_COUNTRY_BLOCKED: &str = "country_blocked";
/// `EVENT_CSP_VIOLATION`.
pub const EVENT_CSP_VIOLATION: &str = "csp_violation";
/// `EVENT_CUSTOM_REQUEST_CHECK`.
pub const EVENT_CUSTOM_REQUEST_CHECK: &str = "custom_request_check";
/// `EVENT_DECODING_ERROR`.
pub const EVENT_DECODING_ERROR: &str = "decoding_error";
/// `EVENT_EMERGENCY_MODE_BLOCK`.
pub const EVENT_EMERGENCY_MODE_BLOCK: &str = "emergency_mode_block";
/// `EVENT_GEO_LOOKUP_FAILED`.
pub const EVENT_GEO_LOOKUP_FAILED: &str = "geo_lookup_failed";
/// `EVENT_PATH_EXCLUDED`.
pub const EVENT_PATH_EXCLUDED: &str = "path_excluded";
/// `EVENT_PATTERN_ADDED`.
pub const EVENT_PATTERN_ADDED: &str = "pattern_added";
/// `EVENT_PATTERN_REMOVED`.
pub const EVENT_PATTERN_REMOVED: &str = "pattern_removed";
/// `EVENT_RATE_LIMITED`.
pub const EVENT_RATE_LIMITED: &str = "rate_limited";
/// `EVENT_RATE_LIMIT_SCRIPT_RELOADED`.
pub const EVENT_RATE_LIMIT_SCRIPT_RELOADED: &str = "rate_limit_script_reloaded";
/// `EVENT_REDIS_CONNECTION`.
pub const EVENT_REDIS_CONNECTION: &str = "redis_connection";
/// `EVENT_REDIS_ERROR`.
pub const EVENT_REDIS_ERROR: &str = "redis_error";
/// `EVENT_ROUTE_UNRESOLVED`.
pub const EVENT_ROUTE_UNRESOLVED: &str = "route_unresolved";
/// `EVENT_SECURITY_BYPASS`.
pub const EVENT_SECURITY_BYPASS: &str = "security_bypass";
/// `EVENT_SECURITY_HEADERS_APPLIED`.
pub const EVENT_SECURITY_HEADERS_APPLIED: &str = "security_headers_applied";
/// `EVENT_USER_AGENT_BLOCKED`.
pub const EVENT_USER_AGENT_BLOCKED: &str = "user_agent_blocked";
/// `EVENT_SUSPICIOUS_REQUEST`.
pub const EVENT_SUSPICIOUS_REQUEST: &str = "suspicious_request";
/// `EVENT_DETECTION_ENGINE_CALLBACK_ERROR`.
pub const EVENT_DETECTION_ENGINE_CALLBACK_ERROR: &str = "detection_engine_callback_error";
/// `EVENT_PATTERN_ANOMALY_TIMEOUT`.
pub const EVENT_PATTERN_ANOMALY_TIMEOUT: &str = "pattern_anomaly_timeout";
/// `EVENT_PATTERN_ANOMALY_SLOW_EXECUTION`.
pub const EVENT_PATTERN_ANOMALY_SLOW_EXECUTION: &str = "pattern_anomaly_slow_execution";
/// `EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY`.
pub const EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY: &str = "pattern_anomaly_statistical_anomaly";

/// Every emitted value, the reference `EVENT_TYPE_VALUES` frozenset.
pub const EVENT_TYPE_VALUES: [&str; 39] = [
    EVENT_PENETRATION_ATTEMPT,
    EVENT_IP_BLOCKED,
    EVENT_IP_BANNED,
    EVENT_IP_BAN_FAILED,
    EVENT_IP_UNBANNED,
    EVENT_CLOUD_BLOCKED,
    EVENT_HTTPS_ENFORCED,
    EVENT_DECORATOR_VIOLATION,
    EVENT_BEHAVIOR_VIOLATION,
    EVENT_PATTERN_DETECTED,
    EVENT_DYNAMIC_RULE_UPDATED,
    EVENT_DYNAMIC_RULE_APPLIED,
    EVENT_DYNAMIC_RULE_VIOLATION,
    EVENT_EMERGENCY_MODE,
    EVENT_ACCESS_DENIED,
    EVENT_AUTHENTICATION_FAILED,
    EVENT_CONTENT_FILTERED,
    EVENT_COUNTRY_BLOCKED,
    EVENT_CSP_VIOLATION,
    EVENT_CUSTOM_REQUEST_CHECK,
    EVENT_DECODING_ERROR,
    EVENT_EMERGENCY_MODE_BLOCK,
    EVENT_GEO_LOOKUP_FAILED,
    EVENT_PATH_EXCLUDED,
    EVENT_PATTERN_ADDED,
    EVENT_PATTERN_REMOVED,
    EVENT_RATE_LIMITED,
    EVENT_RATE_LIMIT_SCRIPT_RELOADED,
    EVENT_REDIS_CONNECTION,
    EVENT_REDIS_ERROR,
    EVENT_ROUTE_UNRESOLVED,
    EVENT_SECURITY_BYPASS,
    EVENT_SECURITY_HEADERS_APPLIED,
    EVENT_USER_AGENT_BLOCKED,
    EVENT_SUSPICIOUS_REQUEST,
    EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
    EVENT_PATTERN_ANOMALY_TIMEOUT,
    EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
    EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn values_are_unique_and_complete() {
        let set: HashSet<&str> = EVENT_TYPE_VALUES.iter().copied().collect();
        assert_eq!(set.len(), EVENT_TYPE_VALUES.len());
    }

    #[test]
    fn spot_check_against_the_reference_file() {
        assert_eq!(EVENT_PENETRATION_ATTEMPT, "penetration_attempt");
        assert_eq!(EVENT_EMERGENCY_MODE, "emergency_mode_activated");
        assert_eq!(
            EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
            "pattern_anomaly_statistical_anomaly"
        );
        assert_eq!(EVENT_REDIS_ERROR, "redis_error");
    }
}
