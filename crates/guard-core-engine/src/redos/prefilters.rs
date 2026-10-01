//! Pattern-safety dispatcher: dangerous constructs and the five structural
//! detectors, in the reference decision order.
//!
//! Port of the reference `_redos_structural_prefilters.py`. Where Python
//! applies `re.search` over the pattern source, this port uses the `regex`
//! crate identically.

use regex::Regex;

use super::ambiguous_tail::detect_ambiguous_optional_tail_in_quantified_group;
use super::literal_in_wildcard::detect_ambiguous_literal_boundary;
use super::structure::{
    detect_adjacent_broad_unbounded_quantifiers, detect_nested_unbounded_quantifier,
};
use super::unreachable_terminator::detect_unreachable_terminator_scan;

const INNER_UNBOUNDED_QUANTIFIER: &str = r"(?:\*|\+|\{[0-9]+,\})";
const OUTER_UNBOUNDED_QUANTIFIER: &str = r"(?:\+|\{[0-9]+,\})";

/// The reference's five structural checks in decision order.
type StructuralCheck = fn(&str) -> Option<String>;

pub(crate) const STRUCTURAL_CHECKS: &[(&str, StructuralCheck)] = &[
    (
        "Pattern contains nested unbounded quantifier: ",
        detect_nested_unbounded_quantifier,
    ),
    (
        "Pattern contains adjacent broad unbounded quantifiers: ",
        detect_adjacent_broad_unbounded_quantifiers,
    ),
    (
        "Pattern contains a broad scan whose terminator cannot be reached by \
         repeating its own prefix: ",
        detect_unreachable_terminator_scan,
    ),
    (
        "Pattern contains a quantified class that can absorb the mandatory \
         literal immediately following it: ",
        detect_ambiguous_literal_boundary,
    ),
    (
        "Pattern contains an ambiguous optional tail inside an unbounded \
         quantified group: ",
        detect_ambiguous_optional_tail_in_quantified_group,
    ),
];

/// First structural violation message, or `None` when clean.
#[must_use]
pub fn first_structural_safety_violation(pattern: &str) -> Option<String> {
    for (message, check) in STRUCTURAL_CHECKS {
        if let Some(finding) = check(pattern) {
            return Some(format!("{message}{finding}"));
        }
    }
    None
}

fn dangerous_construct_patterns() -> Vec<String> {
    vec![
        format!(r"\(\.{INNER}\){OUTER}",
            INNER = INNER_UNBOUNDED_QUANTIFIER,
            OUTER = OUTER_UNBOUNDED_QUANTIFIER),
        format!(r"\([^)]*{INNER}\){OUTER}",
            INNER = INNER_UNBOUNDED_QUANTIFIER,
            OUTER = OUTER_UNBOUNDED_QUANTIFIER),
        format!(r"(?:\.{INNER}){{2,}}", INNER = INNER_UNBOUNDED_QUANTIFIER),
    ]
}

/// Reference `_dangerous_construct_violation`.
#[must_use]
pub fn dangerous_construct_violation(pattern: &str) -> Option<String> {
    for dangerous in dangerous_construct_patterns() {
        if let Ok(checker) = Regex::new(&dangerous)
            && checker.is_match(pattern)
        {
            return Some(format!("Pattern contains dangerous construct: {dangerous}"));
        }
    }
    None
}
