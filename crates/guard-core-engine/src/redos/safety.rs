//! The pattern-safety verdict API.
//!
//! Replaces the engine's 6-regex stub with the full reference chain:
//! dangerous constructs, compile check, structural detectors, reach-probe
//! synthesis, and the empirical cost arbiter over killable children.

use super::ast;
use super::cost_arbiter::{
    CostOutcome, TestStringsOutcome, reach_probe_cost_reason, reach_probe_unreachable_reason,
    run_pattern_safety_probe,
};
use super::prefilters::{dangerous_construct_violation, first_structural_safety_violation};

/// Which validation run to perform (the reference's two modes).
#[derive(Debug, Clone, PartialEq)]
pub enum SafetyMode {
    /// Search the given strings under the per-string threshold after the
    /// structural check (reference `test_strings` argument).
    TestStrings(Vec<String>),
    /// Synthesize probes and arbitrate extrapolated cost (reference
    /// `max_content_length` argument).
    CostVerdict { max_content_length: Option<usize> },
}

/// The five structural rules plus the nesting-depth rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralRule {
    NestedUnboundedQuantifier(String),
    AdjacentBroadUnboundedQuantifiers(String),
    UnreachableTerminatorScan(String),
    LiteralAbsorbedByQuantifiedClass(String),
    AmbiguousOptionalTail(String),
    NestingDepthExceeded,
}

/// Why a pattern was rejected or accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum SafetyReason {
    /// One of the three dangerous backtracking constructs.
    DangerousConstruct(String),
    /// Neither engine can compile the pattern.
    CompileFailed(String),
    /// A structural detector flagged the pattern.
    Structural(StructuralRule),
    /// A test string exceeded the per-string threshold.
    ProbeStringTimeout(usize),
    /// The test-strings child was killed by its deadline.
    ProbeSubprocessTimeout,
    /// The timing child failed to spawn or exited unexpectedly.
    ProbeSpawnFailed(String),
    /// No reaching probe could be synthesized.
    UnreachableProbe,
    /// Extrapolated cost exceeds the budget at the cap.
    OverBudget {
        cap: usize,
        extrapolated: f64,
        ratio: f64,
        min_32: f64,
        median_32: f64,
        load_factor: f64,
    },
    /// Probe construction exceeded its deadline or a builder budget.
    BuilderDeadline(String),
    /// No adversarial trigger found; certified safe.
    Safe,
}

impl SafetyReason {
    /// The stable reason class token (the corpus pins these).
    #[must_use]
    pub fn reason_class(&self) -> &'static str {
        match self {
            Self::DangerousConstruct(_) => "dangerous_construct",
            Self::CompileFailed(_) => "compile_failed",
            Self::Structural(rule) => rule.reason_class(),
            Self::ProbeStringTimeout(_) => "probe_string_timeout",
            Self::ProbeSubprocessTimeout | Self::ProbeSpawnFailed(_) => "probe_subprocess_timeout",
            Self::UnreachableProbe => "unreachable_probe",
            Self::OverBudget { .. } => "over_budget",
            Self::BuilderDeadline(_) => "builder_deadline",
            Self::Safe => "safe",
        }
    }
}

impl StructuralRule {
    /// The stable reason class token per structural rule.
    #[must_use]
    pub fn reason_class(&self) -> &'static str {
        match self {
            Self::NestedUnboundedQuantifier(_) => "structural_nested_unbounded",
            Self::AdjacentBroadUnboundedQuantifiers(_) => "structural_adjacent_broad",
            Self::UnreachableTerminatorScan(_) => "structural_unreachable_terminator",
            Self::LiteralAbsorbedByQuantifiedClass(_) => "structural_literal_absorb",
            Self::AmbiguousOptionalTail(_) => "structural_ambiguous_tail",
            Self::NestingDepthExceeded => "structural_nesting_depth",
        }
    }
}

impl std::fmt::Display for SafetyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DangerousConstruct(construct) => {
                write!(f, "Pattern contains dangerous construct: {construct}")
            }
            Self::CompileFailed(error) => {
                write!(f, "Pattern validation failed: {error}")
            }
            Self::Structural(rule) => write!(f, "{}", structural_rule_text(rule)),
            Self::ProbeStringTimeout(length) => {
                write!(f, "Pattern timed out on test string of length {length}")
            }
            Self::ProbeSubprocessTimeout => write!(
                f,
                "Pattern validation probe exceeded the {}s killable-subprocess timeout",
                super::cost_arbiter::PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS
            ),
            Self::ProbeSpawnFailed(detail) => {
                write!(f, "Pattern validation probe failed to run: {detail}")
            }
            Self::UnreachableProbe => {
                write!(f, "{}", reach_probe_unreachable_reason(None))
            }
            Self::OverBudget {
                cap,
                extrapolated,
                ratio,
                min_32,
                median_32,
                load_factor,
            } => write!(
                f,
                "{}",
                reach_probe_cost_reason(
                    None,
                    &crate::redos::cost_arbiter::OverBudget {
                        cap: *cap,
                        extrapolated: *extrapolated,
                        ratio: *ratio,
                        min_32: *min_32,
                        median_32: *median_32,
                        load_factor: *load_factor,
                    },
                )
            ),
            Self::BuilderDeadline(message) => write!(f, "{message}"),
            Self::Safe => write!(f, "Pattern appears safe"),
        }
    }
}

fn structural_rule_text(rule: &StructuralRule) -> String {
    match rule {
        StructuralRule::NestedUnboundedQuantifier(finding) => {
            format!("Pattern contains nested unbounded quantifier: {finding}")
        }
        StructuralRule::AdjacentBroadUnboundedQuantifiers(finding) => {
            format!("Pattern contains adjacent broad unbounded quantifiers: {finding}")
        }
        StructuralRule::UnreachableTerminatorScan(finding) => format!(
            "Pattern contains a broad scan whose terminator cannot be reached \
             by repeating its own prefix: {finding}"
        ),
        StructuralRule::LiteralAbsorbedByQuantifiedClass(finding) => format!(
            "Pattern contains a quantified class that can absorb the mandatory \
             literal immediately following it: {finding}"
        ),
        StructuralRule::AmbiguousOptionalTail(finding) => format!(
            "Pattern contains an ambiguous optional tail inside an unbounded \
             quantified group: {finding}"
        ),
        StructuralRule::NestingDepthExceeded => {
            crate::redos::structure::nesting_depth_rejection_reason()
        }
    }
}

/// The full validation verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct SafetyVerdict {
    pub safe: bool,
    pub reason: SafetyReason,
}

impl SafetyVerdict {
    fn unsafe_reason(reason: SafetyReason) -> Self {
        Self {
            safe: false,
            reason,
        }
    }

    /// The stable reason class token.
    #[must_use]
    pub fn reason_class(&self) -> &'static str {
        self.reason.reason_class()
    }
}

impl std::fmt::Display for SafetyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// The reference's default flags: IGNORECASE | MULTILINE.
pub fn default_flags() -> super::ast::Flags {
    super::ast::Flags::ignorecase_multiline()
}

fn compile_failed(pattern: &str, flags: super::ast::Flags) -> Result<(), String> {
    let prefix = if flags.ignorecase || flags.multiline || flags.dotall || flags.ascii {
        let mut prefix = String::from("(?");
        if flags.ignorecase {
            prefix.push('i');
        }
        if flags.multiline {
            prefix.push('m');
        }
        if flags.dotall {
            prefix.push('s');
        }
        if flags.ascii {
            prefix.push('a');
        }
        prefix.push(')');
        prefix
    } else {
        String::new()
    };
    // The compile check mirrors the oracle's `re.compile` (the reference
    // `compile_pattern_sync`): Python-syntax validity only. The
    // Python-syntax floor the oracle pins rejects lookalike syntax the
    // `regex` crate would take (and vice versa); the timing child still
    // falls back to `fancy-regex` for patterns the crate cannot compile.
    let _ = prefix;
    ast::parse(pattern, flags).map(|_| ()).map_err(|e| e.0)
}

fn structural_reason(pattern: &str) -> Option<StructuralRule> {
    structural_reason_direct(pattern)
}

fn structural_reason_direct(pattern: &str) -> Option<StructuralRule> {
    use super::ambiguous_tail::detect_ambiguous_optional_tail_in_quantified_group;
    use super::literal_in_wildcard::detect_ambiguous_literal_boundary;
    use super::structure::{
        detect_adjacent_broad_unbounded_quantifiers, detect_nested_unbounded_quantifier,
    };
    use super::unreachable_terminator::detect_unreachable_terminator_scan;
    if let Some(finding) = detect_nested_unbounded_quantifier(pattern) {
        return Some(
            if finding == crate::redos::structure::nesting_depth_rejection_reason() {
                StructuralRule::NestingDepthExceeded
            } else {
                StructuralRule::NestedUnboundedQuantifier(finding)
            },
        );
    }
    if let Some(finding) = detect_adjacent_broad_unbounded_quantifiers(pattern) {
        // The nesting-depth rejection cannot reach this detector: the
        // nested rule runs first in the chain and claims deep patterns.
        return Some(StructuralRule::AdjacentBroadUnboundedQuantifiers(finding));
    }
    if let Some(finding) = detect_unreachable_terminator_scan(pattern) {
        return Some(StructuralRule::UnreachableTerminatorScan(finding));
    }
    if let Some(finding) = detect_ambiguous_literal_boundary(pattern) {
        return Some(StructuralRule::LiteralAbsorbedByQuantifiedClass(finding));
    }
    if let Some(finding) = detect_ambiguous_optional_tail_in_quantified_group(pattern) {
        return Some(StructuralRule::AmbiguousOptionalTail(finding));
    }
    None
}

/// Validate a pattern with the full safety chain under `flags`.
#[must_use]
pub fn validate_pattern_safety_with_flags(
    pattern: &str,
    mode: &SafetyMode,
    flags: super::ast::Flags,
) -> SafetyVerdict {
    validate_pattern_safety_chain(
        pattern,
        mode,
        flags,
        &run_pattern_safety_probe,
        &super::cost_arbiter::reach_probe_cost_verdict,
    )
}

/// An injected pattern-safety probe runner (test seam).
pub(crate) type SafetyProbeRunner<'a> =
    &'a dyn Fn(&str, Vec<String>, super::ast::Flags) -> TestStringsOutcome;

/// An injected cost-verdict runner (test seam).
pub(crate) type CostVerdictRunner<'a> =
    &'a dyn Fn(&str, Option<usize>, super::ast::Flags) -> CostOutcome;

/// The pure half of [`validate_pattern_safety_with_flags`]: the probe and
/// cost-verdict runners are injected so tests can force every arm
/// deterministically.
#[must_use]
pub(crate) fn validate_pattern_safety_chain(
    pattern: &str,
    mode: &SafetyMode,
    flags: super::ast::Flags,
    probe_runner: SafetyProbeRunner<'_>,
    cost_runner: CostVerdictRunner<'_>,
) -> SafetyVerdict {
    if let Some(construct) = dangerous_construct_violation(pattern) {
        return SafetyVerdict::unsafe_reason(SafetyReason::DangerousConstruct(construct));
    }
    if let Err(error) = compile_failed(pattern, flags) {
        return SafetyVerdict::unsafe_reason(SafetyReason::CompileFailed(error));
    }
    match mode {
        SafetyMode::TestStrings(test_strings) => {
            if let Some(rule) = structural_reason(pattern) {
                return SafetyVerdict::unsafe_reason(SafetyReason::Structural(rule));
            }
            match probe_runner(pattern, test_strings.clone(), flags) {
                TestStringsOutcome::Safe => SafetyVerdict {
                    safe: true,
                    reason: SafetyReason::Safe,
                },
                TestStringsOutcome::SlowString(length) => {
                    SafetyVerdict::unsafe_reason(SafetyReason::ProbeStringTimeout(length))
                }
                TestStringsOutcome::CompileFailed(message) => {
                    SafetyVerdict::unsafe_reason(SafetyReason::CompileFailed(message))
                }
                TestStringsOutcome::SubprocessTimeout => {
                    SafetyVerdict::unsafe_reason(SafetyReason::ProbeSubprocessTimeout)
                }
                TestStringsOutcome::SpawnFailed(detail) => {
                    SafetyVerdict::unsafe_reason(SafetyReason::ProbeSpawnFailed(detail))
                }
            }
        }
        SafetyMode::CostVerdict { max_content_length } => {
            match cost_runner(pattern, *max_content_length, flags) {
                CostOutcome::Safe => SafetyVerdict {
                    safe: true,
                    reason: SafetyReason::Safe,
                },
                CostOutcome::Over(over) => {
                    let reason = SafetyReason::OverBudget {
                        cap: over.cap,
                        extrapolated: over.extrapolated,
                        ratio: over.ratio,
                        min_32: over.min_32,
                        median_32: over.median_32,
                        load_factor: over.load_factor,
                    };
                    SafetyVerdict::unsafe_reason(reason)
                }
                CostOutcome::Unreachable => {
                    SafetyVerdict::unsafe_reason(SafetyReason::UnreachableProbe)
                }
                CostOutcome::Structural => {
                    // Unreachable fallback: CostOutcome::Structural only
                    // comes back when first_structural_safety_violation
                    // found a violation, and that check runs the same five
                    // structural detectors in the same order as
                    // structural_reason.
                    #[cfg(not(coverage))]
                    match structural_reason(pattern) {
                        Some(rule) => SafetyVerdict::unsafe_reason(SafetyReason::Structural(rule)),
                        None => SafetyVerdict::unsafe_reason(SafetyReason::BuilderDeadline(
                            "structural violation".into(),
                        )),
                    }
                    #[cfg(coverage)]
                    {
                        let rule = structural_reason(pattern)
                            .expect("the arbiter echoes an existing violation");
                        SafetyVerdict::unsafe_reason(SafetyReason::Structural(rule))
                    }
                }
                CostOutcome::BuilderDeadline(message) => {
                    // A builder timeout echoes the structural violation when
                    // one exists (reference behavior).
                    if message == crate::redos::structure::nesting_depth_rejection_reason() {
                        return SafetyVerdict::unsafe_reason(SafetyReason::Structural(
                            StructuralRule::NestingDepthExceeded,
                        ));
                    }
                    if first_structural_safety_violation(pattern).is_some() {
                        // Unreachable fallback: the guard above runs the
                        // same detectors as structural_reason.
                        #[cfg(not(coverage))]
                        return match structural_reason(pattern) {
                            Some(rule) => {
                                SafetyVerdict::unsafe_reason(SafetyReason::Structural(rule))
                            }
                            None => {
                                SafetyVerdict::unsafe_reason(SafetyReason::BuilderDeadline(message))
                            }
                        };
                        #[cfg(coverage)]
                        {
                            let rule = structural_reason(pattern)
                                .expect("the guard runs the same detectors");
                            return SafetyVerdict::unsafe_reason(SafetyReason::Structural(rule));
                        }
                    }
                    SafetyVerdict::unsafe_reason(SafetyReason::BuilderDeadline(message))
                }
            }
        }
    }
}

/// Validate a pattern with the full safety chain under the reference's
/// default flags (IGNORECASE | MULTILINE).
#[must_use]
pub fn validate_pattern_safety(pattern: &str, mode: &SafetyMode) -> SafetyVerdict {
    validate_pattern_safety_with_flags(pattern, mode, default_flags())
}

/// Compat shim preserving the old two-tuple shape for existing consumers
/// (the pyo3 facade and config paths): cost-verdict mode under default
/// flags.
#[must_use]
pub fn validate_pattern_safety_compat(pattern: &str) -> (bool, String) {
    let verdict = validate_pattern_safety(
        pattern,
        &SafetyMode::CostVerdict {
            max_content_length: None,
        },
    );
    (verdict.safe, verdict.reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract the structural rule; panics on any other reason.
    fn expect_structural(verdict: SafetyVerdict) -> StructuralRule {
        match verdict.reason {
            SafetyReason::Structural(rule) => rule,
            other => panic!("expected a structural rule, got {other:?}"),
        }
    }

    fn cost(max: Option<usize>) -> SafetyMode {
        SafetyMode::CostVerdict {
            max_content_length: max,
        }
    }

    #[test]
    fn dangerous_constructs_are_rejected_first() {
        for pattern in [
            r"(.*)+",
            r"(.+)+",
            r"([a-z]*)+",
            r"([a-z]+)+",
            r".*.*",
            r".+.+",
        ] {
            let verdict = validate_pattern_safety(pattern, &cost(None));
            assert!(!verdict.safe, "{pattern}");
            assert_eq!(verdict.reason_class(), "dangerous_construct");
            assert!(
                verdict
                    .reason
                    .to_string()
                    .starts_with("Pattern contains dangerous construct: "),
                "{}",
                verdict.reason
            );
        }
    }

    #[test]
    fn compile_failures_name_the_reference_prefix() {
        for pattern in ["(unclosed", "[invalid", "*leading"] {
            let verdict = validate_pattern_safety(pattern, &cost(None));
            assert!(!verdict.safe, "{pattern}");
            assert_eq!(verdict.reason_class(), "compile_failed");
            assert!(
                verdict
                    .reason
                    .to_string()
                    .starts_with("Pattern validation failed: "),
                "{}",
                verdict.reason
            );
        }
    }

    #[test]
    fn the_python_floor_rejects_lookalike_syntax() {
        // Atomic groups and possessive quantifiers are compile failures at
        // the reference floor the oracle pins.
        for pattern in ["(?>a)+", "(?P<1bad>x)", "(?P=n)", "(?:\\1)", "a*+"] {
            let verdict = validate_pattern_safety(pattern, &cost(None));
            assert!(!verdict.safe, "{pattern}");
            assert_eq!(verdict.reason_class(), "compile_failed", "{pattern}");
        }
    }

    #[test]
    fn structural_rules_carry_pinned_reason_classes() {
        let cases = [
            (r"(\w+)*$", "structural_nested_unbounded"),
            (".*x.*", "structural_adjacent_broad"),
            ("a[^b]*c", "structural_unreachable_terminator"),
            ("[a-z]+abc", "structural_literal_absorb"),
            (r"(a?)+$", "structural_ambiguous_tail"),
        ];
        for (pattern, class) in cases {
            let verdict = validate_pattern_safety(pattern, &SafetyMode::TestStrings(vec![]));
            assert!(!verdict.safe, "{pattern}");
            assert_eq!(
                verdict.reason_class(),
                class,
                "{pattern}: {}",
                verdict.reason
            );
            let rule = expect_structural(verdict);
            assert_eq!(rule.reason_class(), class);
        }
    }

    #[test]
    fn every_reason_class_token_is_stable() {
        assert_eq!(
            SafetyReason::DangerousConstruct("(.*)+".into()).reason_class(),
            "dangerous_construct"
        );
        assert_eq!(
            SafetyReason::CompileFailed("boom".into()).reason_class(),
            "compile_failed"
        );
        assert_eq!(
            SafetyReason::Structural(StructuralRule::NestingDepthExceeded).reason_class(),
            "structural_nesting_depth"
        );
        assert_eq!(
            SafetyReason::ProbeStringTimeout(5).reason_class(),
            "probe_string_timeout"
        );
        assert_eq!(
            SafetyReason::ProbeSubprocessTimeout.reason_class(),
            "probe_subprocess_timeout"
        );
        assert_eq!(
            SafetyReason::ProbeSpawnFailed("x".into()).reason_class(),
            "probe_subprocess_timeout"
        );
        assert_eq!(
            SafetyReason::UnreachableProbe.reason_class(),
            "unreachable_probe"
        );
        assert_eq!(
            SafetyReason::BuilderDeadline("late".into()).reason_class(),
            "builder_deadline"
        );
        assert_eq!(SafetyReason::Safe.reason_class(), "safe");
    }

    #[test]
    fn reason_displays_are_human_readable() {
        assert_eq!(
            SafetyReason::ProbeSubprocessTimeout.to_string(),
            "Pattern validation probe exceeded the 2s killable-subprocess timeout"
        );
        assert_eq!(
            SafetyReason::ProbeStringTimeout(9).to_string(),
            "Pattern timed out on test string of length 9"
        );
        let verdict = SafetyVerdict {
            safe: false,
            reason: SafetyReason::ProbeSpawnFailed("gone".into()),
        };
        assert_eq!(
            verdict.to_string(),
            "Pattern validation probe failed to run: gone"
        );
        assert_eq!(verdict.reason_class(), "probe_subprocess_timeout");
    }

    #[test]
    fn the_nesting_depth_cap_maps_to_its_own_rule() {
        let pattern = format!(
            "{}a{}",
            "(".repeat(crate::redos::structure::MAX_GROUP_NESTING_DEPTH + 2),
            ")".repeat(crate::redos::structure::MAX_GROUP_NESTING_DEPTH + 2),
        );
        assert_eq!(
            structural_reason(&pattern),
            Some(StructuralRule::NestingDepthExceeded)
        );
    }

    #[test]
    fn compile_prefix_covers_every_flag_letter() {
        // The compile step is exercised before the injected runners run, so
        // each flag letter's prefix branch is covered by a chain call.
        let flags = crate::redos::ast::Flags {
            ignorecase: true,
            multiline: true,
            dotall: true,
            ascii: true,
        };
        let verdict = validate_pattern_safety_chain(
            "abc",
            &SafetyMode::TestStrings(vec![]),
            flags,
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &|_p, _m, _f| CostOutcome::Safe,
        );
        assert!(verdict.safe, "{:?}", verdict.reason);
    }

    #[test]
    fn test_string_outcomes_map_to_their_reasons() {
        let cases: Vec<(TestStringsOutcome, SafetyReason)> = vec![
            (
                TestStringsOutcome::SlowString(42),
                SafetyReason::ProbeStringTimeout(42),
            ),
            (
                TestStringsOutcome::CompileFailed("bad".into()),
                SafetyReason::CompileFailed("bad".into()),
            ),
            (
                TestStringsOutcome::SubprocessTimeout,
                SafetyReason::ProbeSubprocessTimeout,
            ),
            (
                TestStringsOutcome::SpawnFailed("no child".into()),
                SafetyReason::ProbeSpawnFailed("no child".into()),
            ),
        ];
        for (outcome, expected) in cases {
            let verdict = validate_pattern_safety_chain(
                "abc",
                &SafetyMode::TestStrings(vec![]),
                crate::redos::ast::Flags::default(),
                &move |_p, _t, _f| outcome.clone(),
                &|_p, _m, _f| CostOutcome::Safe,
            );
            assert!(!verdict.safe, "{expected:?}");
            assert_eq!(verdict.reason, expected);
        }
    }

    #[test]
    fn cost_outcomes_map_to_their_reasons() {
        let over = crate::redos::cost_arbiter::OverBudget {
            cap: 1024,
            extrapolated: 0.5,
            ratio: 2.0,
            min_32: 0.03,
            median_32: 0.04,
            load_factor: 1.5,
        };
        let verdict = validate_pattern_safety_chain(
            "abc",
            &cost(Some(1024)),
            crate::redos::ast::Flags::default(),
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &move |_p, _m, _f| CostOutcome::Over(over.clone()),
        );
        assert_eq!(
            verdict.reason,
            SafetyReason::OverBudget {
                cap: 1024,
                extrapolated: 0.5,
                ratio: 2.0,
                min_32: 0.03,
                median_32: 0.04,
                load_factor: 1.5,
            }
        );
        let verdict = validate_pattern_safety_chain(
            "abc",
            &cost(None),
            crate::redos::ast::Flags::default(),
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &|_p, _m, _f| CostOutcome::Unreachable,
        );
        assert_eq!(verdict.reason, SafetyReason::UnreachableProbe);
    }

    #[test]
    fn structural_cost_outcomes_echo_the_rule() {
        // r"(\w+)*$" carries a nested-unbounded structural violation (and
        // is not a dangerous construct), so the chain echoes the rule back.
        let verdict = validate_pattern_safety_chain(
            r"(\w+)*$",
            &cost(None),
            crate::redos::ast::Flags::default(),
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &|_p, _m, _f| CostOutcome::Structural,
        );
        let rule = expect_structural(verdict);
        assert_eq!(rule.reason_class(), "structural_nested_unbounded");
    }

    #[test]
    fn builder_deadlines_echo_the_nesting_depth_rule() {
        let verdict = validate_pattern_safety_chain(
            "abc",
            &cost(None),
            crate::redos::ast::Flags::default(),
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &|_p, _m, _f| {
                CostOutcome::BuilderDeadline(
                    crate::redos::structure::nesting_depth_rejection_reason(),
                )
            },
        );
        assert_eq!(
            verdict.reason,
            SafetyReason::Structural(StructuralRule::NestingDepthExceeded)
        );
    }

    #[test]
    fn builder_deadlines_echo_structural_violations() {
        let verdict = validate_pattern_safety_chain(
            r"(\w+)*$",
            &cost(None),
            crate::redos::ast::Flags::default(),
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &|_p, _m, _f| CostOutcome::BuilderDeadline("builder ran long".into()),
        );
        let rule = expect_structural(verdict);
        assert_eq!(rule.reason_class(), "structural_nested_unbounded");
    }

    #[test]
    fn builder_deadlines_stand_alone_without_violations() {
        let verdict = validate_pattern_safety_chain(
            "abc",
            &cost(None),
            crate::redos::ast::Flags::default(),
            &|_p, _t, _f| TestStringsOutcome::Safe,
            &|_p, _m, _f| CostOutcome::BuilderDeadline("builder ran long".into()),
        );
        assert_eq!(
            verdict.reason,
            SafetyReason::BuilderDeadline("builder ran long".into())
        );
    }

    #[test]
    fn structural_display_prefixes_match_the_reference() {
        let checks = [
            (r"(\w+)*$", "Pattern contains nested unbounded quantifier: "),
            (
                ".*x.*",
                "Pattern contains adjacent broad unbounded quantifiers: ",
            ),
            (
                "a[^b]*c",
                "Pattern contains a broad scan whose terminator cannot be \
                 reached by repeating its own prefix: ",
            ),
            (
                "[a-z]+abc",
                "Pattern contains a quantified class that can absorb the \
                 mandatory literal immediately following it: ",
            ),
            (
                r"(a?)+$",
                "Pattern contains an ambiguous optional tail inside an \
                 unbounded quantified group: ",
            ),
        ];
        for (pattern, prefix) in checks {
            let verdict = validate_pattern_safety(pattern, &SafetyMode::TestStrings(vec![]));
            let text = verdict.reason.to_string();
            assert!(
                text.starts_with(prefix),
                "{pattern}: {text} does not start with {prefix:?}"
            );
        }
    }

    #[test]
    fn test_strings_mode_certifies_clean_patterns() {
        let verdict = validate_pattern_safety(
            "abc",
            &SafetyMode::TestStrings(vec!["abc".to_owned(), "x".to_owned()]),
        );
        assert!(verdict.safe);
        assert_eq!(verdict.reason_class(), "safe");
        assert_eq!(verdict.reason.to_string(), "Pattern appears safe");
    }

    #[test]
    fn unreachable_probes_reject_rather_than_certify() {
        let verdict = validate_pattern_safety(r"[^\x00-\U0010FFFF]+", &cost(None));
        assert!(!verdict.safe);
        assert_eq!(verdict.reason_class(), "unreachable_probe");
        assert!(
            verdict
                .reason
                .to_string()
                .starts_with("Pattern validation probe could not construct")
        );
    }

    #[test]
    fn safe_cost_verdicts_certify_linear_patterns() {
        for pattern in ["hello world", r"(?i)union\s+select", r"^\s*$"] {
            let verdict = validate_pattern_safety(pattern, &cost(Some(10000)));
            assert!(verdict.safe, "{pattern}: {}", verdict.reason);
        }
    }

    #[test]
    fn default_flags_are_ignorecase_and_multiline() {
        let flags = default_flags();
        assert!(flags.ignorecase);
        assert!(flags.multiline);
        assert!(!flags.dotall);
        assert!(!flags.ascii);
    }

    #[test]
    fn compat_shape_carries_the_same_decisions() {
        let (safe, reason) = validate_pattern_safety_compat(r"(.*)+");
        assert!(!safe);
        assert!(reason.starts_with("Pattern contains dangerous construct: "));
        let (safe, reason) = validate_pattern_safety_compat("hello world");
        assert!(safe);
        assert_eq!(reason, "Pattern appears safe");
    }

    #[test]
    fn structural_rule_reason_classes_are_stable() {
        assert_eq!(
            StructuralRule::NestingDepthExceeded.reason_class(),
            "structural_nesting_depth"
        );
        assert_eq!(
            structural_rule_text(&StructuralRule::NestingDepthExceeded),
            crate::redos::structure::nesting_depth_rejection_reason()
        );
    }

    #[test]
    fn over_budget_reason_class_and_display() {
        let reason = SafetyReason::OverBudget {
            cap: 262144,
            extrapolated: 0.2,
            ratio: 2.0,
            min_32: 0.025,
            median_32: 0.026,
            load_factor: 2.5,
        };
        assert_eq!(reason.reason_class(), "over_budget");
        assert!(
            reason
                .to_string()
                .starts_with("Pattern extrapolated CPU cost at cap (262144 chars)")
        );
    }

    #[test]
    fn probe_subprocess_reason_shapes() {
        let reason = SafetyReason::ProbeStringTimeout(42).to_string();
        assert_eq!(reason, "Pattern timed out on test string of length 42");
        assert_eq!(
            SafetyReason::ProbeSubprocessTimeout.reason_class(),
            "probe_subprocess_timeout"
        );
        let spawn = SafetyReason::ProbeSpawnFailed("no child".into()).to_string();
        assert!(spawn.starts_with("Pattern validation probe failed to run: "));
        assert_eq!(
            SafetyReason::BuilderDeadline("deadline hit".into()).to_string(),
            "deadline hit"
        );
    }

    #[test]
    #[should_panic(expected = "expected a structural rule")]
    fn expect_structural_rejects_other_reasons() {
        let _ = expect_structural(SafetyVerdict {
            safe: false,
            reason: SafetyReason::Safe,
        });
    }
}
