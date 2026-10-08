//! The behavior-rule engine, ported from the reference behavior handler
//! and its mixins. The go port is the structural template.
//!
//! Reference sources: `guard_core/handlers/behavior_handler.py`
//! (`BehaviorTracker`, `BehaviorRule`, `config_to_rule`), the
//! response-pattern mixin (`_behavior_response_pattern.py` +
//! `_behavior_json_pattern.py`), and the action dispatch
//! (`_behavior_action_dispatch.py`).
//!
//! The engine owns the tracking and the verdict; the caller supplies the
//! response facts (status code and the already-captured body prefix) and
//! receives the action to dispatch. The body prefix is the caller's
//! capture, bounded by the reference
//! `behavior_max_response_body_inspect_bytes` budget: `status:` patterns
//! never touch it, and the other pattern kinds see only the leading
//! prefix.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::behavior::{BehaviorAction, BehaviorRule, BehaviorTracker};
//! use std::time::SystemTime;
//!
//! let mut tracker = BehaviorTracker::new();
//! let rule = BehaviorRule {
//!     rule_type: "return_pattern".to_owned(),
//!     threshold: 2,
//!     window: 3600,
//!     pattern: "status:404".to_owned(),
//!     action: "ban".to_owned(),
//!     ban_duration: Some(900),
//!     correlate_with_detection: false,
//! };
//! let now = SystemTime::now();
//! // Two 404s stay below a threshold of 2 (`len(timestamps) > threshold`).
//! assert!(!tracker.track_return_pattern("GET:/api", "192.0.2.10", 404, None, &rule, 262_144, now));
//! assert!(!tracker.track_return_pattern("GET:/api", "192.0.2.10", 404, None, &rule, 262_144, now));
//! // The third crossing trips the rule ...
//! assert!(tracker.track_return_pattern("GET:/api", "192.0.2.10", 404, None, &rule, 262_144, now));
//! // ... and the dispatch decides what happens: a ban for 900s.
//! assert_eq!(
//!     BehaviorTracker::dispatch_action(&rule, "192.0.2.10", false),
//!     BehaviorAction::Ban { duration: 900 }
//! );
//! ```

use std::collections::HashMap;
use std::time::SystemTime;

use regex::Regex;

/// The reference `BehaviorRule`, field for field.
///
/// Only `return_pattern` rules are tracked today, like the go port;
/// `usage` and `frequency` rules construct but the caller drives them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct BehaviorRule {
    /// `usage`, `return_pattern`, or `frequency`.
    pub rule_type: String,
    pub threshold: u32,
    /// Sliding-window size in seconds.
    pub window: u64,
    /// `status:<code>`, `json:<path>==<expected>`, `regex:<pattern>`, or a
    /// bare (case-insensitive) substring.
    pub pattern: String,
    /// `ban`, `log`, `throttle`, or `alert`.
    pub action: String,
    /// The ban length override for the `ban` action; `None` falls back to
    /// the reference 3600s default.
    pub ban_duration: Option<u64>,
    /// The reference `correlate_with_detection`: halves the effective
    /// threshold while the caller reports live detection categories for
    /// the IP (not modeled yet, matching the go port's fail-closed note).
    pub correlate_with_detection: bool,
}

/// What `apply_action` decided for one tripped rule: the observable part
/// of the reference `BehaviorActionDispatchMixin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorAction {
    /// The active-mode `ban`: hold the IP for this many seconds (the rule's
    /// `ban_duration`, else the reference 3600s default).
    Ban {
        /// The ban length in seconds.
        duration: u64,
    },
    /// `alert`, `log`, and `throttle` reduce to an observable note today,
    /// exactly like the go port: the reference logs at the suspicious
    /// level and (for alert) critical, which this port does not model.
    Note {
        /// The configured action string.
        action: String,
    },
    /// Passive mode never executes the action: the reference logs
    /// `[PASSIVE MODE]` lines only, so no ban is ever recorded.
    LoggedOnly,
}

impl BehaviorAction {
    /// Whether the action is the active-mode `ban` (the usage-rule
    /// consumer's dispatch check).
    #[must_use]
    pub const fn is_ban(&self) -> bool {
        matches!(self, Self::Ban { .. })
    }
}

/// The reference `BehaviorTracker`'s in-memory return-pattern windows.
///
/// The redis-free fallback: `pattern_key -> client_ip -> timestamps`,
/// with the same sliding-window arithmetic (`len(timestamps) > threshold`).
#[derive(Default)]
#[allow(clippy::struct_field_names)]
pub struct BehaviorTracker {
    return_patterns: HashMap<String, HashMap<String, Vec<f64>>>,
    status_patterns: HashMap<String, u16>,
    regex_patterns: HashMap<String, Regex>,
    /// The usage windows: `endpoint_id -> client_ip -> timestamps` (the
    /// reference `usage_counts` bucket shape, `track_endpoint_usage`'s
    /// in-memory store).
    usage_counts: HashMap<String, HashMap<String, Vec<f64>>>,
}

/// The default response-body prefix the reference reads for a non-`status:`
/// pattern (`behavior_max_response_body_inspect_bytes` default, 262144).
pub const DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES: usize = 262_144;

impl BehaviorTracker {
    /// A fresh tracker, the harness `BehaviorTracker(config)` with clean
    /// windows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every window (the per-case reset the harness performs).
    pub fn reset(&mut self) {
        self.return_patterns.clear();
        self.status_patterns.clear();
        self.regex_patterns.clear();
        self.usage_counts.clear();
    }

    /// `track_endpoint_usage`: record one request observation for
    /// `(endpoint_id, client_ip)` inside the rule's window, and answer
    /// whether the rule tripped (`len(timestamps) > threshold`, the
    /// reference's strict comparison). `now` is the caller's clock (the
    /// reference `time.time()` float; [`unix_now`] converts).
    pub fn track_endpoint_usage(
        &mut self,
        endpoint_id: &str,
        client_ip: &str,
        rule: &BehaviorRule,
        now: f64,
    ) -> bool {
        let window_start = now - f64::from(u32::try_from(rule.window).unwrap_or(u32::MAX));
        let bucket = self.usage_counts.entry(endpoint_id.to_owned()).or_default();
        let timestamps = bucket.entry(client_ip.to_owned()).or_default();
        timestamps.retain(|ts| *ts >= window_start);
        timestamps.push(now);
        timestamps.len() > usize::try_from(rule.threshold).unwrap_or(usize::MAX)
    }

    /// `get_recent_event_count`: how many tracked events any endpoint
    /// recorded for `ip` inside `window_seconds` (the reference walks
    /// every endpoint bucket's timestamps for the identity).
    #[must_use]
    pub fn get_recent_event_count(&self, ip: &str, window_seconds: u64, now: f64) -> usize {
        if ip.is_empty() {
            return 0;
        }
        let cutoff = now - f64::from(u32::try_from(window_seconds).unwrap_or(u32::MAX));
        self.usage_counts
            .values()
            .filter_map(|bucket| bucket.get(ip))
            .map(|timestamps| timestamps.iter().filter(|ts| **ts >= cutoff).count())
            .sum()
    }

    /// `track_return_pattern`: record one response observation for
    /// `(endpoint_id, client_ip)` when the response matches the rule's
    /// pattern, and answer whether the rule tripped
    /// (`len(timestamps) > threshold` inside the rule's window).
    ///
    /// `status` and `body_prefix` are the response facts: `body_prefix` is
    /// the caller's capture bounded by the inspect-bytes budget and only
    /// read when the pattern needs the body and the caller has
    /// `behavior_scan_response_body` enabled. `now` is the caller's clock
    /// (the reference `time.time()` float); [`SystemTime`] converts via
    /// [`unix_now`].
    #[allow(clippy::too_many_arguments)]
    pub fn track_return_pattern(
        &mut self,
        endpoint_id: &str,
        client_ip: &str,
        status: u16,
        body_prefix: Option<&[u8]>,
        rule: &BehaviorRule,
        max_inspect_bytes: usize,
        now: SystemTime,
    ) -> bool {
        if rule.rule_type != "return_pattern" {
            return false;
        }
        let matched =
            self.check_response_pattern(status, body_prefix, &rule.pattern, max_inspect_bytes);
        if matched != Some(true) {
            // `None` (the pattern could not be evaluated, e.g. a body
            // pattern with no captured prefix) is a no-match, exactly like
            // the reference `_check_response_pattern` returning None and
            // the mixin treating it as no violation.
            return false;
        }
        let now = unix_now(now);
        let window_start = now - f64::from(u32::try_from(rule.window).unwrap_or(u32::MAX));
        let pattern_key = format!("{endpoint_id}:{}", rule.pattern);
        let timestamps = self
            .return_patterns
            .entry(pattern_key)
            .or_default()
            .entry(client_ip.to_owned())
            .or_default();
        timestamps.retain(|ts| *ts >= window_start);
        timestamps.push(now);
        timestamps.len() > rule.threshold as usize
    }

    /// `_check_response_pattern`: `Some(true/false)` when the pattern was
    /// evaluated, `None` when it could not be (a body pattern while no
    /// body prefix was captured).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn check_response_pattern(
        &mut self,
        status: u16,
        body_prefix: Option<&[u8]>,
        pattern: &str,
        max_inspect_bytes: usize,
    ) -> Option<bool> {
        if let Some(expected) = pattern.strip_prefix("status:") {
            let expected: u16 = expected.trim().parse().ok()?;
            return Some(status == expected);
        }
        // Everything below needs the response body: without the caller's
        // scan flag the reference never reads it and the rule never
        // matches, so a missing prefix is "could not evaluate".
        let body = body_prefix?;
        let body_str = String::from_utf8_lossy(&body[..body.len().min(max_inspect_bytes)]);
        if let Some(json_pattern) = pattern.strip_prefix("json:") {
            let parsed = serde_json::from_str::<serde_json::Value>(&body_str).ok()?;
            return Some(match_json_pattern(&parsed, json_pattern));
        }
        if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
            if !self.regex_patterns.contains_key(regex_pattern) {
                let Ok(regex) = Regex::new(&format!("(?i){regex_pattern}")) else {
                    return None;
                };
                self.regex_patterns.insert(regex_pattern.to_owned(), regex);
            }
            let regex = &self.regex_patterns[regex_pattern];
            return Some(regex.is_match(&body_str));
        }
        Some(body_str.to_lowercase().contains(&pattern.to_lowercase()))
    }

    /// `BehaviorActionDispatchMixin.apply_action`: passive mode only logs
    /// (so [`BehaviorAction::LoggedOnly`]), active mode bans with the rule
    /// duration override (else the reference 3600s default) or reduces to
    /// a note. The caller applies the ban to its IP-ban store; the
    /// reference ban reason is `behavioral_violation`.
    #[must_use]
    pub fn dispatch_action(
        rule: &BehaviorRule,
        client_ip: &str,
        passive_mode: bool,
    ) -> BehaviorAction {
        let _ = client_ip;
        if passive_mode {
            return BehaviorAction::LoggedOnly;
        }
        if rule.action == "ban" {
            return BehaviorAction::Ban {
                duration: rule.ban_duration.unwrap_or(3600),
            };
        }
        BehaviorAction::Note {
            action: rule.action.clone(),
        }
    }
}

/// The reference `config_to_rule`: the corpus config dict shape.
#[must_use]
pub fn rule_from_config(cfg: &serde_json::Value) -> Option<BehaviorRule> {
    let obj = cfg.as_object()?;
    Some(BehaviorRule {
        rule_type: obj.get("rule_type")?.as_str()?.to_owned(),
        threshold: u32::try_from(obj.get("threshold")?.as_u64()?).ok()?,
        window: obj
            .get("window")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3600),
        pattern: obj
            .get("pattern")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        action: obj
            .get("action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("log")
            .to_owned(),
        ban_duration: obj.get("ban_duration").and_then(serde_json::Value::as_u64),
        correlate_with_detection: obj
            .get("correlate_with_detection")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

/// `time.time()` as the tracker's float Unix timestamp.
#[must_use]
pub fn unix_now(now: SystemTime) -> f64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

/// `BehaviorJsonPatternMixin._match_json_pattern`: `path.to.field ==
/// expected` with case-insensitive comparison, a `[]` segment matching any
/// array element, and any structural mismatch or parse failure counting as
/// no-match.
#[must_use]
fn match_json_pattern(data: &serde_json::Value, pattern: &str) -> bool {
    let Some((path, expected)) = pattern.split_once("==") else {
        return false;
    };
    let expected = expected.trim().trim_matches(['\'', '"']);
    let mut current = data;
    for part in path.trim().split('.') {
        if let Some(field) = part.strip_suffix("[]") {
            return match_json_array(current, field, expected);
        }
        let Some(next) = current.get(part) else {
            return false;
        };
        current = next;
    }
    json_scalar_to_string(current).eq_ignore_ascii_case(expected)
}

fn match_json_array(current: &serde_json::Value, field: &str, expected: &str) -> bool {
    let Some(list) = current.get(field).and_then(serde_json::Value::as_array) else {
        return false;
    };
    list.iter()
        .any(|item| json_scalar_to_string(item).eq_ignore_ascii_case(expected))
}

/// Python `str()` over the JSON-decoded scalar: booleans lowercase, null
/// as `None`, numbers via shortest round-trip formatting.
#[must_use]
fn json_scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(true) => "true".to_owned(),
        serde_json::Value::Bool(false) => "false".to_owned(),
        serde_json::Value::Null => "None".to_owned(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, threshold: u32) -> BehaviorRule {
        BehaviorRule {
            rule_type: "return_pattern".to_owned(),
            threshold,
            window: 3600,
            pattern: pattern.to_owned(),
            action: "ban".to_owned(),
            ban_duration: Some(900),
            correlate_with_detection: false,
        }
    }

    #[test]
    fn the_action_dispatch_predicate_names_the_ban() {
        assert!(BehaviorAction::Ban { duration: 3600 }.is_ban());
        assert!(
            !BehaviorAction::Note {
                action: String::from("log")
            }
            .is_ban()
        );
        assert!(!BehaviorAction::LoggedOnly.is_ban());
    }

    #[test]
    fn usage_windows_count_per_identity_and_trip_at_the_threshold() {
        let base = BehaviorRule {
            rule_type: "usage".to_owned(),
            threshold: 2,
            window: 60,
            pattern: String::new(),
            action: "ban".to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        };
        let mut tracker = BehaviorTracker::new();
        // Two observations: under the strict threshold.
        assert!(!tracker.track_endpoint_usage("GET:/api", "192.0.2.10", &base, 1_000.0));
        assert!(!tracker.track_endpoint_usage("GET:/api", "192.0.2.10", &base, 1_001.0));
        // The third observation crosses (len > threshold).
        assert!(tracker.track_endpoint_usage("GET:/api", "192.0.2.10", &base, 1_002.0));
        // A second identity counts independently.
        assert!(!tracker.track_endpoint_usage("GET:/api", "192.0.2.11", &base, 1_003.0));
        // A second endpoint counts independently for the same identity.
        assert!(!tracker.track_endpoint_usage("POST:/api", "192.0.2.10", &base, 1_004.0));

        // The full history answers inside a wide window.
        assert_eq!(
            tracker.get_recent_event_count("192.0.2.10", 3_600, 1_050.0),
            4
        );
        // Sliding: a 60s window read at 1062 drops the 1000/1001 stamps.
        assert_eq!(tracker.get_recent_event_count("192.0.2.10", 60, 1_062.0), 2);
        // The reference's empty-identity guard.
        assert_eq!(tracker.get_recent_event_count("", 60, 1_050.0), 0);

        // Re-crossing after the slide: the stale stamps drop first.
        assert!(!tracker.track_endpoint_usage("GET:/api", "192.0.2.10", &base, 1_070.0));
    }

    #[test]
    fn status_pattern_trips_above_the_threshold_only() {
        let mut tracker = BehaviorTracker::new();
        let rule = rule("status:404", 2);
        let now = SystemTime::now();
        assert!(!tracker.track_return_pattern("GET:/api", "192.0.2.10", 404, None, &rule, 1, now));
        assert!(!tracker.track_return_pattern("GET:/api", "192.0.2.10", 404, None, &rule, 1, now));
        assert!(tracker.track_return_pattern("GET:/api", "192.0.2.10", 404, None, &rule, 1, now));
        // Another IP counts separately.
        assert!(!tracker.track_return_pattern("GET:/api", "192.0.2.11", 404, None, &rule, 1, now));
        // A non-matching status never records.
        assert!(!tracker.track_return_pattern("GET:/api", "192.0.2.11", 200, None, &rule, 1, now));
    }

    #[test]
    fn sliding_window_forgotten_timestamps_do_not_count() {
        let mut tracker = BehaviorTracker::new();
        let rule = rule("status:404", 1);
        let epoch = SystemTime::UNIX_EPOCH;
        let t = |secs: u64| epoch + std::time::Duration::from_secs(secs);
        assert!(!tracker.track_return_pattern(
            "GET:/api",
            "192.0.2.10",
            404,
            None,
            &rule,
            1,
            t(10_000)
        ));
        // Inside the window the second hit crosses `> 1`.
        assert!(tracker.track_return_pattern(
            "GET:/api",
            "192.0.2.10",
            404,
            None,
            &rule,
            1,
            t(10_100)
        ));
        // Outside the 3600s window both hits no longer count, so this
        // is hit number one again: below `> 1`.
        assert!(!tracker.track_return_pattern(
            "GET:/api",
            "192.0.2.10",
            404,
            None,
            &rule,
            1,
            t(50_000)
        ));
        assert!(tracker.track_return_pattern(
            "GET:/api",
            "192.0.2.10",
            404,
            None,
            &rule,
            1,
            t(50_100)
        ));
    }

    #[test]
    fn body_patterns_match_like_the_reference() {
        let mut tracker = BehaviorTracker::new();
        let body = b"{\"error\": \"not found\", \"items\": [1, 2]}".as_slice();
        let checks = [
            ("regex:NOT FOUND", Some(true)),
            ("not found", Some(true)),
            ("missing", Some(false)),
            ("json:error==Not Found", Some(true)),
            ("json:items[]==2", Some(true)),
            ("json:items[]==3", Some(false)),
            ("json:nope==x", Some(false)),
            ("json:broken", Some(false)),
        ];
        for (pattern, want) in checks {
            assert_eq!(
                tracker.check_response_pattern(
                    200,
                    Some(body),
                    pattern,
                    DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES
                ),
                want,
                "pattern {pattern}"
            );
        }
        // Body patterns without a captured prefix cannot evaluate.
        assert_eq!(
            tracker.check_response_pattern(
                200,
                None,
                "not found",
                DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES
            ),
            None
        );
    }

    #[test]
    fn dispatch_matches_the_reference_action_semantics() {
        let ban = rule("status:404", 1);
        assert_eq!(
            BehaviorTracker::dispatch_action(&ban, "192.0.2.10", false),
            BehaviorAction::Ban { duration: 900 }
        );
        let no_duration = BehaviorRule {
            ban_duration: None,
            ..rule("status:404", 1)
        };
        assert_eq!(
            BehaviorTracker::dispatch_action(&no_duration, "192.0.2.10", false),
            BehaviorAction::Ban { duration: 3600 }
        );
        assert_eq!(
            BehaviorTracker::dispatch_action(&ban, "192.0.2.10", true),
            BehaviorAction::LoggedOnly,
            "passive mode never executes the action"
        );
        let log_rule = BehaviorRule {
            action: "log".to_owned(),
            ..rule("status:404", 1)
        };
        assert_eq!(
            BehaviorTracker::dispatch_action(&log_rule, "192.0.2.10", false),
            BehaviorAction::Note {
                action: "log".to_owned()
            }
        );
    }

    #[test]
    fn rule_from_config_reads_the_corpus_shape() {
        let cfg = serde_json::json!({
            "rule_type": "return_pattern",
            "threshold": 2,
            "window": 3600,
            "pattern": "status:404",
            "action": "ban",
            "ban_duration": 900
        });
        assert_eq!(rule_from_config(&cfg), Some(rule("status:404", 2)));
    }

    #[test]
    fn malformed_configs_answer_none_instead_of_erroring() {
        // a bare array is not an object
        assert_eq!(rule_from_config(&serde_json::json!([])), None);
        // the rule_type key is missing or not a string
        assert_eq!(rule_from_config(&serde_json::json!({})), None);
        assert_eq!(
            rule_from_config(&serde_json::json!({ "rule_type": 7 })),
            None
        );
        // the threshold key is missing, not a number, or out of u32 range
        assert_eq!(
            rule_from_config(&serde_json::json!({ "rule_type": "return_pattern" })),
            None
        );
        assert_eq!(
            rule_from_config(&serde_json::json!({
                "rule_type": "return_pattern",
                "threshold": "many",
            })),
            None
        );
        assert_eq!(
            rule_from_config(&serde_json::json!({
                "rule_type": "return_pattern",
                "threshold": 5_000_000_000u64,
            })),
            None
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn now(&self) -> SystemTime {
            let secs = self.0.load(Ordering::Relaxed);
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
        }
    }

    fn return_rule(threshold: u32) -> BehaviorRule {
        BehaviorRule {
            rule_type: "return_pattern".to_owned(),
            threshold,
            window: 60,
            pattern: "status:403".to_owned(),
            action: "log".to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        }
    }

    #[test]
    fn reset_forgets_every_window() {
        let fake = FakeClock::default();
        let mut tracker = BehaviorTracker::new();
        let rule = return_rule(1);
        assert!(!tracker.track_return_pattern("ep", "1.2.3.4", 403, None, &rule, 1024, fake.now()));
        tracker.reset();
        // after the reset the window is gone: the same observation is the
        // first hit again, not a threshold cross
        assert!(!tracker.track_return_pattern("ep", "1.2.3.4", 403, None, &rule, 1024, fake.now()));
    }

    #[test]
    fn non_return_rules_and_unevaluated_patterns_never_trip() {
        let fake = FakeClock::default();
        let mut tracker = BehaviorTracker::new();
        let frequency = BehaviorRule {
            rule_type: "frequency".to_owned(),
            threshold: 0,
            window: 60,
            pattern: String::new(),
            action: "log".to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        };
        // a body pattern with no captured prefix cannot be evaluated
        let body_rule = BehaviorRule {
            pattern: "regex:secret".to_owned(),
            ..return_rule(0)
        };
        assert!(!tracker.track_return_pattern(
            "ep",
            "1.2.3.4",
            403,
            None,
            &frequency,
            1024,
            fake.now()
        ));
        assert!(!tracker.track_return_pattern(
            "ep",
            "1.2.3.4",
            403,
            None,
            &body_rule,
            1024,
            fake.now()
        ));
    }

    #[test]
    fn json_scalars_render_like_python_str() {
        use crate::behavior::json_scalar_to_string;
        assert_eq!(json_scalar_to_string(&serde_json::json!(true)), "true");
        assert_eq!(json_scalar_to_string(&serde_json::json!(false)), "false");
        assert_eq!(json_scalar_to_string(&serde_json::json!(null)), "None");
        assert_eq!(json_scalar_to_string(&serde_json::json!(1)), "1");
    }

    #[test]
    fn json_array_membership_matches_any_element() {
        use crate::behavior::match_json_array;
        let value = serde_json::json!({"tags": ["a", "b"]});
        assert!(match_json_array(&value, "tags", "B"));
        assert!(!match_json_array(&value, "tags", "c"));
        assert!(!match_json_array(&value, "missing", "a"));
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    fn rule(pattern: &str) -> BehaviorRule {
        BehaviorRule {
            rule_type: "return_pattern".to_owned(),
            threshold: 1,
            window: 3600,
            pattern: pattern.to_owned(),
            action: "log".to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        }
    }

    #[test]
    fn an_uncompilable_regex_pattern_cannot_be_evaluated() {
        let mut tracker = BehaviorTracker::new();
        assert_eq!(
            tracker.check_response_pattern(200, Some(b"body"), "regex:([unclosed", 1024),
            None
        );
        // and the rule treats "could not evaluate" as a no-match
        let now = SystemTime::now();
        assert!(!tracker.track_return_pattern(
            "GET:/x",
            "192.0.2.9",
            200,
            Some(b"body"),
            &rule("regex:([unclosed"),
            1024,
            now,
        ));
    }

    #[test]
    fn a_compiled_regex_pattern_is_cached_across_calls() {
        let mut tracker = BehaviorTracker::new();
        let first = tracker.check_response_pattern(200, Some(b"error text"), "regex:err\\w+", 1024);
        assert_eq!(first, Some(true));
        // the second call reuses the cached compile
        let second =
            tracker.check_response_pattern(200, Some(b"error text"), "regex:err\\w+", 1024);
        assert_eq!(second, Some(true));
    }

    #[test]
    fn an_object_valued_json_field_never_matches_a_scalar_expectation() {
        let mut tracker = BehaviorTracker::new();
        let body = br#"{"meta":{"a":1}}"#;
        assert_eq!(
            tracker.check_response_pattern(200, Some(body), "json:meta==zzz", 1024),
            Some(false)
        );
    }

    #[test]
    fn unevaluable_patterns_answer_none() {
        let mut tracker = BehaviorTracker::new();
        // a status rule with a non-numeric target cannot be evaluated
        assert_eq!(
            tracker.check_response_pattern(200, Some(b"b"), "status:soon", 1024),
            None
        );
        // a json rule over a non-JSON body cannot be evaluated
        assert_eq!(
            tracker.check_response_pattern(200, Some(b"not json"), "json:a==1", 1024),
            None
        );
    }
}
