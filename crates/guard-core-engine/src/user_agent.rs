//! The blocked user-agent pattern filter.
//!
//! This is the Rust family's port of the reference engine's user-agent
//! matching (`guard_core/core/checks/helpers.py::check_user_agent_allowed`
//! and `guard_core/_utils/access_control.py::is_user_agent_allowed`, backed
//! by `guard_core/_utils/detection_scan.py::_user_agent_matches_blocked_pattern`).
//! One call, [`UserAgentFilter::is_blocked`], answers whether a
//! `User-Agent` header value matches any configured blocked pattern:
//!
//! ```text
//! subject = user_agent truncated to the first 512 code points
//! blocked = any pattern matches the subject (search semantics,
//!           case-insensitive, multiline)
//! ```
//!
//! The config constructor mirrors the reference's
//! `_validate_blocked_user_agents_value`: every entry is a regular
//! expression, and a pattern the ReDoS validator flags is a config error
//! (the reference raises `ValueError` at config construction). This port
//! also fails closed on an entry the regex engine cannot compile - the
//! reference would instead raise at request time and trip the pipeline's
//! fail-secure 500, so the failure moves earlier without changing what a
//! valid config does.
//!
//! Matching semantics mirror the reference compiler exactly: the Python
//! side compiles with `re.IGNORECASE | re.MULTILINE` and scans with
//! `finditer` (search semantics, not fullmatch), and the 512-code-point
//! truncation is `_MAX_USER_AGENT_MATCH_LENGTH`. Patterns are evaluated in
//! configured order and the first match wins.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::user_agent::UserAgentFilter;
//!
//! let filter = UserAgentFilter::new(["sqlmap", r"^\S*\(compatible; Googlebot\)"])
//!     .expect("valid patterns");
//!
//! // Search semantics: a substring match is enough, case-insensitively.
//! assert!(filter.is_blocked("Mozilla/5.0 (sqlmap/1.8)"));
//! assert!(filter.is_blocked("SQLMAP"));
//! assert!(!filter.is_blocked("Mozilla/5.0 (X11; Linux x86_64)"));
//!
//! // A missing User-Agent header reads as the empty string, which only a
//! // pattern targeting emptiness can block.
//! assert!(!filter.is_blocked(""));
//!
//! // The default (no patterns) never blocks.
//! assert!(!UserAgentFilter::default().is_blocked("sqlmap"));
//! ```

use std::fmt;

use regex::Regex;

use crate::compiler;

/// The match subject cap: a `User-Agent` header value is truncated to its
/// first 512 code points before pattern evaluation
/// (`_MAX_USER_AGENT_MATCH_LENGTH` in the reference).
pub const MAX_USER_AGENT_MATCH_LENGTH: usize = 512;

/// An invalid `blocked_user_agents` entry: the config error
/// [`UserAgentFilter::new`] fails closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgentConfigError {
    /// The rejected pattern.
    pub entry: String,
    /// Why it was rejected (the ReDoS validator's reason, or the compile
    /// error).
    pub reason: String,
}

impl fmt::Display for UserAgentConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid blocked_user_agents pattern '{}': {}",
            self.entry, self.reason
        )
    }
}

impl std::error::Error for UserAgentConfigError {}

/// The compiled blocked user-agent patterns.
///
/// Build it once at startup with [`UserAgentFilter::new`] (which fails
/// closed on an unsafe or uncompilable pattern) and evaluate header values
/// with [`UserAgentFilter::is_blocked`]. The default value holds no
/// patterns and never blocks. Cheap to clone; clones share the compiled
/// regexes.
#[derive(Debug, Clone, Default)]
pub struct UserAgentFilter {
    patterns: Vec<Regex>,
}

impl UserAgentFilter {
    /// Compile and validate the blocked patterns, failing closed on the
    /// first rejected entry.
    ///
    /// Every entry is validated with the engine's ReDoS validator (the
    /// reference's `validate_pattern_safety`, max content length 512) and
    /// compiled case-insensitive + multiline, the reference compiler's
    /// flags.
    ///
    /// # Errors
    ///
    /// [`UserAgentConfigError`] naming the first entry that is flagged
    /// ReDoS-unsafe or that the regex engine cannot compile.
    pub fn new<I, S>(patterns: I) -> Result<Self, UserAgentConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut compiled = Vec::new();
        for pattern in patterns {
            let pattern = pattern.as_ref();
            let verdict = crate::redos::validate_pattern_safety(
                pattern,
                &crate::redos::SafetyMode::CostVerdict {
                    // The reference validates UA rules against the max
                    // user-agent match length (512).
                    max_content_length: Some(MAX_USER_AGENT_MATCH_LENGTH),
                },
            );
            let (is_safe, reason) = (verdict.safe, verdict.reason.to_string());
            if !is_safe {
                return Err(UserAgentConfigError {
                    entry: pattern.to_owned(),
                    reason: format!("rejected by ReDoS validator ({reason})"),
                });
            }
            let regex = compiler::compile(pattern).map_err(|error| UserAgentConfigError {
                entry: pattern.to_owned(),
                reason: format!("expected a compilable regular expression ({error})"),
            })?;
            compiled.push(regex);
        }
        Ok(Self { patterns: compiled })
    }

    /// Compile app-authored blocked patterns without the `ReDoS`
    /// subprocess validation, keeping the compile semantics
    /// (case-insensitive + multiline, the reference compiler's flags).
    ///
    /// This is the per-request lane for the reference's per-route
    /// `RouteConfig.blocked_user_agents`: the Python reference runs the
    /// route list through the same matcher per request (`fnmatch`-based,
    /// no safety validation on the per-request path), and the adapter
    /// route resolver hands over app-authored lists whose patterns the
    /// application itself authored. Config-file surfaces (the global
    /// `blocked_user_agents`) must keep using [`UserAgentFilter::new`],
    /// which validates every entry with the engine's `ReDoS` validator.
    ///
    /// # Errors
    ///
    /// [`UserAgentConfigError`] naming the first entry the regex engine
    /// cannot compile.
    pub fn from_trusted_patterns<I, S>(patterns: I) -> Result<Self, UserAgentConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut compiled = Vec::new();
        for pattern in patterns {
            let pattern = pattern.as_ref();
            let regex = compiler::compile(pattern).map_err(|error| UserAgentConfigError {
                entry: pattern.to_owned(),
                reason: format!("expected a compilable regular expression ({error})"),
            })?;
            compiled.push(regex);
        }
        Ok(Self { patterns: compiled })
    }

    /// Whether the `User-Agent` value matches any blocked pattern.
    ///
    /// The subject is the value truncated to its first
    /// [`MAX_USER_AGENT_MATCH_LENGTH`] code points (the reference's
    /// `_MAX_USER_AGENT_MATCH_LENGTH` slice); matching is search semantics
    /// under the reference's case-insensitive + multiline flags. A missing
    /// header reads as the empty string.
    #[must_use]
    pub fn is_blocked(&self, user_agent: &str) -> bool {
        let subject: String = user_agent
            .chars()
            .take(MAX_USER_AGENT_MATCH_LENGTH)
            .collect();
        self.patterns.iter().any(|regex| regex.is_match(&subject))
    }

    /// How many patterns the filter holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether the filter holds no patterns (it never blocks).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_is_empty_and_never_blocks() {
        let filter = UserAgentFilter::default();
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);
        for agent in ["sqlmap", "", "Mozilla/5.0"] {
            assert!(
                !filter.is_blocked(agent),
                "{agent} must pass an empty filter"
            );
        }
    }

    #[test]
    fn trusted_patterns_keep_the_compile_semantics_without_the_subprocess() {
        let filter = UserAgentFilter::from_trusted_patterns(["sqlmap", "havij"])
            .expect("compilable patterns");
        assert!(filter.is_blocked("Mozilla/5.0 (SQLMAP/1.8)"));
        assert!(filter.is_blocked("user agent: HaViJ probe"));
        assert!(!filter.is_blocked("Mozilla/5.0 (compatible)"));

        // An uncompilable entry still fails closed (compile errors are
        // independent of the safety subprocess).
        let error = UserAgentFilter::from_trusted_patterns(["(["]).unwrap_err();
        assert_eq!(error.entry, "([");
    }

    #[test]
    fn matches_are_search_semantics_case_insensitive() {
        let filter = UserAgentFilter::new(["sqlmap", "havij"]).expect("valid patterns");
        assert_eq!(filter.len(), 2);
        assert!(filter.is_blocked("sqlmap"));
        assert!(filter.is_blocked("Mozilla/5.0 (SQLMAP/1.8)"));
        assert!(filter.is_blocked("user agent: HaViJ probe"));
        assert!(
            filter.is_blocked("innocent-looking sqlmapbot client"),
            "search semantics: any substring occurrence is enough"
        );
        assert!(!filter.is_blocked("Mozilla/5.0 (X11; Linux x86_64)"));
    }

    #[test]
    fn patterns_are_multiline_and_anchored_patterns_behave_like_python() {
        // ^ with MULTILINE anchors per line, like the reference compiler's
        // re.IGNORECASE | re.MULTILINE.
        let filter = UserAgentFilter::new(["^bot/"]).expect("valid pattern");
        assert!(filter.is_blocked("bot/1.0"));
        assert!(!filter.is_blocked("see bot/1.0"));
    }

    #[test]
    fn subject_is_truncated_to_512_code_points() {
        let filter = UserAgentFilter::new(["tail-marker"]).expect("valid pattern");
        let mut agent = "a".repeat(600);
        agent.push_str(" tail-marker");
        assert!(
            !filter.is_blocked(&agent),
            "a match living past the 512-code-point cap must not block"
        );
        let mut inside = "x".repeat(500);
        inside.push_str(" tail-marker");
        assert!(
            filter.is_blocked(&inside),
            "a match inside the cap must block"
        );
        // Code points, not bytes: the cap lands past a multi-byte prefix.
        let mut multibyte = "\u{00e9}".repeat(500);
        multibyte.push_str("tail-marker");
        assert!(filter.is_blocked(&multibyte));
    }

    #[test]
    fn missing_header_reads_as_the_empty_string() {
        let filter = UserAgentFilter::new(["^$"]).expect("valid pattern");
        assert!(filter.is_blocked(""), "an empty value matches ^$");
        assert!(!filter.is_blocked("Mozilla/5.0"));
    }

    #[test]
    fn new_fails_closed_on_an_uncompilable_pattern() {
        // The full safety chain validates every entry first, so an
        // uncompilable pattern is rejected there (the validator subsumes
        // the compile check).
        let error = UserAgentFilter::new(["(unclosed"]).unwrap_err();
        assert_eq!(error.entry, "(unclosed");
        assert!(
            error.reason.starts_with("rejected by ReDoS validator ("),
            "unexpected reason: {}",
            error.reason
        );
        assert!(
            error
                .to_string()
                .starts_with("invalid blocked_user_agents pattern '(unclosed':"),
            "unexpected display: {error}"
        );
    }

    #[test]
    fn new_fails_closed_on_a_redos_unsafe_pattern() {
        // Nested quantifiers are the canonical catastrophic-backtracking
        // shape the reference validator rejects.
        let error = UserAgentFilter::new(["(a+)+b"]).unwrap_err();
        assert_eq!(error.entry, "(a+)+b");
        assert!(
            error.reason.contains("rejected by ReDoS validator"),
            "unexpected reason: {}",
            error.reason
        );
        assert!(
            error
                .to_string()
                .starts_with("invalid blocked_user_agents pattern '(a+)+b':")
        );
    }

    #[test]
    fn first_rejected_entry_wins_and_valid_prefixes_are_not_retained() {
        let error = UserAgentFilter::new(["sqlmap", "(bad", "worse]"]).unwrap_err();
        assert_eq!(error.entry, "(bad");
    }

    #[test]
    fn clone_shares_nothing_observable() {
        let filter = UserAgentFilter::new(["sqlmap"]).expect("valid pattern");
        let clone = filter.clone();
        assert!(clone.is_blocked("SQLMAP"));
        assert_eq!(clone.len(), filter.len());
    }

    #[test]
    fn a_chain_safe_pattern_the_engine_cannot_compile_is_rejected() {
        // Lookarounds pass the Python-syntax safety chain but the concrete
        // engine compiler rejects them, so the config constructor fails.
        let error = UserAgentFilter::new(["(?=x)a"]).expect_err("rejected");
        assert_eq!(error.entry, "(?=x)a");
        assert!(
            error
                .reason
                .starts_with("expected a compilable regular expression"),
            "{}",
            error.reason
        );
    }
}
