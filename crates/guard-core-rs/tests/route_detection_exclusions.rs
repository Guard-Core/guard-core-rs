//! End-to-end adapter wiring for the per-route detection exclusion surface:
//! resolve the global config plus the matched route, scan the request
//! surfaces, translate the verdict into the pipeline's `ThreatFinding`, and
//! feed the rate-limit/ban stage - the exact chain a tower adapter runs,
//! with the route layer standing in for `request.state.route_config`.

use guard_core_rs::detect::DetectConfig;
use guard_core_rs::detection_exclusions::{
    DetectionExclusionConfig, RequestSurfaces, RouteDetectionExclusions, check_applies, resolve,
    scan_request,
};
use guard_core_rs::tower::{
    IpBanConfig, IpGateDecision, RateLimitConfig, RateLimitStage, RateLimitStageConfig,
    ThreatFinding,
};
use std::net::IpAddr;
use std::str::FromStr;

const fn corpus_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
        max_scan_values: 512,
        max_scan_chars: 65_536,
        max_json_depth: 32,
    }
}

/// The adapter's route table: the exclusion sets per path, what the
/// reference hangs off `RouteConfig` and the decorators attach.
fn route_for(path: &str) -> RouteDetectionExclusions {
    if path == "/internal/metrics" {
        // The route disables the body surface and disables every category
        // (an empty Some), overriding the global config both directions.
        return RouteDetectionExclusions {
            detection_scan_body: Some(false),
            enabled_detection_categories: Some(Vec::new()),
            excluded_detection_params: Some(vec!["secret".to_owned()]),
            ..RouteDetectionExclusions::default()
        };
    }
    if path == "/search" {
        // The route narrows detection to sqli only.
        return RouteDetectionExclusions {
            enabled_detection_categories: Some(vec!["sqli".to_owned()]),
            excluded_detection_body_fields: Some(vec!["session_blob".to_owned()]),
            ..RouteDetectionExclusions::default()
        };
    }
    RouteDetectionExclusions::default()
}

fn global_config() -> DetectionExclusionConfig {
    DetectionExclusionConfig {
        excluded_detection_params: vec!["debug".to_owned()],
        ..DetectionExclusionConfig::default()
    }
}

fn scan(path: &str, query: &[(&str, &str)], body: &str, content_type: &str) -> ThreatFinding {
    let exclusions = resolve(Some(&global_config()), Some(&route_for(path)));
    let query_params: Vec<(String, String)> = query
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let verdict = scan_request(
        &RequestSurfaces {
            url_path: Some(path),
            query_params: &query_params,
            headers: &[],
            content_type,
            raw_body: body,
        },
        &exclusions,
        &corpus_config(),
    );
    if verdict.is_threat {
        ThreatFinding {
            is_threat: true,
            categories: verdict.categories,
            trigger_info: verdict.reason,
        }
    } else {
        ThreatFinding {
            is_threat: false,
            categories: Vec::new(),
            trigger_info: String::new(),
        }
    }
}

fn ip(text: &str) -> IpAddr {
    IpAddr::from_str(text).expect("test address")
}

fn stage() -> RateLimitStage {
    RateLimitStage::new(RateLimitStageConfig {
        rate_limit: RateLimitConfig {
            rate_limit: 1_000,
            ..RateLimitConfig::default()
        },
        ip_ban: IpBanConfig {
            enable_ip_banning: true,
            auto_ban_threshold: 2,
            ..IpBanConfig::default()
        },
        passive_mode: false,
        custom_error_responses: std::collections::HashMap::new(),
    })
    .expect("valid stage config")
}

#[test]
fn default_route_excludes_nothing_beyond_the_global_config() {
    let finding = scan("/public", &[("debug", "1 UNION SELECT password")], "", "");
    assert!(
        !finding.is_threat,
        "the global excluded param never detects"
    );
    let finding = scan("/public", &[("q", "<script>alert(1)</script>")], "", "");
    assert!(finding.is_threat, "an unexcluded param still detects");
    assert_eq!(finding.categories, vec!["xss"]);
}

#[test]
fn route_param_exclusion_skips_the_excluded_param_only() {
    // `/internal/metrics` excludes `secret`; an attack in it stays clean.
    let finding = scan(
        "/internal/metrics",
        &[("secret", "1 UNION SELECT password")],
        "",
        "",
    );
    assert!(!finding.is_threat, "the excluded param did not contribute");

    // The same attack on another param of the same route still detects if
    // any category were enabled - here every category is disabled by the
    // route, so it stays clean; on the default route it detects.
    let finding = scan("/public", &[("secret", "1 UNION SELECT password")], "", "");
    assert!(finding.is_threat);
    assert_eq!(finding.categories, vec!["sqli"]);
}

#[test]
fn route_category_narrowing_disables_the_other_categories() {
    // XSS on `/search`: the route enables sqli only, so the xss payload is
    // filtered and nothing detects.
    let finding = scan("/search", &[("q", "<script>alert(1)</script>")], "", "");
    assert!(!finding.is_threat, "xss is not enabled on /search");

    // SQLi on `/search`: the enabled category detects.
    let finding = scan("/search", &[("q", "1 UNION SELECT password")], "", "");
    assert!(finding.is_threat);
    assert_eq!(finding.categories, vec!["sqli"]);
}

#[test]
fn route_body_field_exclusion_skips_the_field_only() {
    let body = "session_blob=<script>alert(1)</script>&comment=1 UNION SELECT password";
    let finding = scan("/search", &[], body, "application/x-www-form-urlencoded");
    assert!(finding.is_threat, "the untouched field still scans");
    assert_eq!(
        finding.categories,
        vec!["sqli"],
        "the excluded field contributed nothing"
    );

    // The excluded field alone stays clean (its xss payload is also not an
    // enabled category on this route, but the field is skipped outright).
    let finding = scan(
        "/search",
        &[],
        "session_blob=<script>alert(1)</script>",
        "application/x-www-form-urlencoded",
    );
    assert!(!finding.is_threat);

    // The same payload in a non-excluded field would be filtered by the
    // category narrowing, not by the exclusion - a control for the
    // exclusion actually doing the work above.
    let finding = scan(
        "/search",
        &[],
        "other=<script>alert(1)</script>",
        "application/x-www-form-urlencoded",
    );
    assert!(
        !finding.is_threat,
        "xss is not an enabled category on /search"
    );
}

#[test]
fn route_scan_body_false_skips_the_body_but_not_the_rest() {
    let body = "payload=<script>alert(1)</script>";
    // On `/internal/metrics` the body does not scan.
    let finding = scan(
        "/internal/metrics",
        &[],
        body,
        "application/x-www-form-urlencoded",
    );
    assert!(!finding.is_threat, "the body surface is off on this route");

    // The same body detects on a route with the body surface on.
    let finding = scan("/public", &[], body, "application/x-www-form-urlencoded");
    assert!(finding.is_threat);
    assert_eq!(finding.categories, vec!["xss"]);
}

#[test]
fn the_detection_feed_bans_through_the_shared_stage() {
    // The adapter translates the verdict into a `ThreatFinding` and feeds
    // the stage: below the threshold the request answers the 400
    // "Suspicious activity detected" contract body, and the second
    // crossing (threshold 2) answers the crossing-ban shape on the same
    // request, the family's 403 "IP has been banned".
    let stage = stage();
    let attacker = ip("192.0.2.100");
    let finding = scan("/public", &[("q", "<script>alert(1)</script>")], "", "");
    assert!(finding.is_threat);

    let flagged = stage
        .decide_for_path(Some(attacker), Some("/public"), None, None, Some(&finding))
        .expect("below the threshold the request still answers the 400");
    assert_eq!(flagged.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(flagged.body, "Suspicious activity detected");
    let answer = stage
        .decide_for_path(Some(attacker), Some("/public"), None, None, Some(&finding))
        .expect("threshold crossed");
    assert_eq!(answer.status, http::StatusCode::FORBIDDEN);
    assert_eq!(answer.body, "IP has been banned");
    assert!(stage.bans().is_banned(attacker));

    // The excluded attack never counts: the verdict is clean, so the
    // stage sees no finding at all.
    let excluded = scan(
        "/internal/metrics",
        &[("secret", "1 UNION SELECT password")],
        "",
        "",
    );
    assert!(!excluded.is_threat);
    assert!(
        stage
            .decide_for_path(
                Some(ip("192.0.2.101")),
                Some("/internal/metrics"),
                None,
                None,
                Some(&excluded)
            )
            .is_none()
    );
    assert!(!stage.bans().is_banned(ip("192.0.2.101")));
    assert_eq!(
        stage.counters().tracked_ips(),
        1,
        "only the real attacker counted"
    );
}

#[test]
fn route_toggles_keep_the_check_alive_and_override_both_ways() {
    // Request-time: the matched route's toggle wins over the global flag.
    assert!(guard_core_rs::detection_exclusions::detection_enabled(
        false,
        Some(true)
    ));
    assert!(!guard_core_rs::detection_exclusions::detection_enabled(
        true,
        Some(false)
    ));

    // Liveness: the check stays constructed while any route enables it,
    // even with the global flag off.
    assert!(check_applies(false, [false, true, false], false));
    assert!(!check_applies(false, [false, false], false));
}

#[test]
fn the_whitelist_gate_still_skips_detection_entirely() {
    // The route surface shapes what scans; the global skip state (an
    // `IpGateDecision` whitelist match) skips the feed outright.
    let stage = stage();
    let whitelisted = ip("192.0.2.102");
    let gate = IpGateDecision {
        is_whitelisted: true,
        is_exempt: false,
    };
    let finding = scan("/public", &[("q", "<script>alert(1)</script>")], "", "");
    assert!(finding.is_threat);
    assert!(
        stage
            .decide_for_path(
                Some(whitelisted),
                Some("/public"),
                None,
                Some(gate),
                Some(&finding)
            )
            .is_none()
    );
    assert_eq!(
        stage.counters().tracked_ips(),
        0,
        "a whitelisted IP never feeds"
    );
}
