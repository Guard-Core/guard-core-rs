//! Broad-scan unreachable-terminator detection.
//!
//! Port of the reference `_redos_unreachable_terminator.py`: a linear walk
//! tracking the literal prefix characters a broad scan (`.` or `[...]`
//! quantified) cannot absorb, and the terminator characters that follow.

use std::collections::BTreeSet;

use super::structure::{outer_quantifier_len, skip_char_class};

const PREFIX_RESET_CHARS: &str = "()|^$";
const TERMINATOR_NON_LITERAL_LEADERS: &str = "()|^$.*+?{";

fn skip_symbol_quantifier_at(text: &[char], k: usize) -> usize {
    let mut end = k + 1;
    if end < text.len() && text[end] == '?' {
        end += 1;
    }
    end - k
}

fn skip_brace_quantifier_at(text: &[char], k: usize) -> usize {
    let Some(offset) = text[k..].iter().position(|c| *c == '}') else {
        return 0;
    };
    let end_brace = k + offset;
    let inner: String = text[k + 1..end_brace].iter().collect();
    let parts: Vec<&str> = inner.split(',').collect();
    if !parts
        .iter()
        .all(|p| p.is_empty() || p.chars().all(|c| c.is_ascii_digit()))
        || parts.iter().all(|p| p.is_empty())
    {
        return 0;
    }
    let mut end = end_brace + 1;
    if end < text.len() && text[end] == '?' {
        end += 1;
    }
    end - k
}

fn skip_quantifier_at(text: &[char], k: usize) -> usize {
    if k >= text.len() {
        return 0;
    }
    match text[k] {
        '*' | '+' | '?' => skip_symbol_quantifier_at(text, k),
        '{' => skip_brace_quantifier_at(text, k),
        _ => 0,
    }
}

fn quantifier_at_allows_zero(text: &[char], k: usize) -> bool {
    if skip_quantifier_at(text, k) == 0 {
        return false;
    }
    match text[k] {
        '*' | '?' => true,
        '{' => {
            let end_brace = text[k..].iter().position(|c| *c == '}').map(|o| k + o);
            let Some(end_brace) = end_brace else {
                return false;
            };
            let low: String = text[k + 1..end_brace]
                .iter()
                .collect::<String>()
                .split(',')
                .next()
                .unwrap_or("")
                .to_owned();
            low.is_empty() || low == "0"
        }
        _ => false,
    }
}

/// The terminator character set at `j`; `None` when not a positive literal
/// class (reference `_terminator_chars_at`).
#[must_use]
pub fn terminator_chars_at(text: &str, j: usize) -> Option<BTreeSet<char>> {
    let chars: Vec<char> = text.chars().collect();
    terminator_chars_at_slice(&chars, j)
}

fn terminator_chars_at_slice(chars: &[char], j: usize) -> Option<BTreeSet<char>> {
    if j >= chars.len() {
        return None;
    }
    let c = chars[j];
    if c == '[' {
        let end = skip_char_class(chars, j);
        let inner: String = chars[j + 1..end - 1].iter().collect();
        if inner.starts_with('^') || inner.is_empty() {
            return None;
        }
        return Some(inner.chars().collect());
    }
    if c == '\\' && j + 1 < chars.len() {
        let next = chars[j + 1];
        return if next.is_alphanumeric() {
            None
        } else {
            Some(BTreeSet::from([next]))
        };
    }
    if TERMINATOR_NON_LITERAL_LEADERS.contains(c) {
        return None;
    }
    Some(BTreeSet::from([c]))
}

fn broad_scan_excluded_chars(pattern: &[char], i: usize) -> (usize, Option<BTreeSet<char>>) {
    let c = pattern[i];
    if c == '.' {
        return (i + 1, Some(BTreeSet::new()));
    }
    let j = skip_char_class(pattern, i);
    let inner: String = pattern[i + 1..j - 1].iter().collect();
    if !inner.starts_with('^') {
        return (j, None);
    }
    (j, Some(inner[1..].chars().collect()))
}

type StepResult = (usize, BTreeSet<char>, Option<String>);

fn class_terminator_finding(
    pattern: &[char],
    i: usize,
    scan_end: usize,
    prefix_chars: &BTreeSet<char>,
    excluded: &BTreeSet<char>,
) -> Option<String> {
    if outer_quantifier_len(pattern, scan_end) == 0 {
        return None;
    }
    let term_pos = scan_end + skip_quantifier_at(pattern, scan_end);
    let terminator_chars = terminator_chars_at_slice(pattern, term_pos);
    if let (Some(terminator), false) = (terminator_chars, prefix_chars.is_empty()) {
        let excluded_hit = prefix_chars.intersection(excluded).next().is_some();
        let terminator_hit = prefix_chars.intersection(&terminator).next().is_some();
        if !excluded_hit && !terminator_hit {
            let scanned: String = pattern[i..scan_end].iter().collect();
            let sorted: String = prefix_chars.iter().collect();
            return Some(format!("{scanned} preceded by {sorted}"));
        }
    }
    None
}

fn broad_scan_step(pattern: &[char], i: usize, prefix_chars: &BTreeSet<char>) -> StepResult {
    let (scan_end, excluded) = broad_scan_excluded_chars(pattern, i);
    let Some(excluded) = excluded else {
        return (scan_end, BTreeSet::new(), None);
    };
    if let Some(finding) = class_terminator_finding(pattern, i, scan_end, prefix_chars, &excluded) {
        return (scan_end, prefix_chars.clone(), Some(finding));
    }
    let next_i = scan_end + skip_quantifier_at(pattern, scan_end);
    (next_i, BTreeSet::new(), None)
}

fn escape_step(
    pattern: &[char],
    i: usize,
    prefix_chars: &BTreeSet<char>,
) -> (usize, BTreeSet<char>) {
    let next = pattern[i + 1];
    let token_end = i + 2;
    let next_prefix = if !next.is_alphanumeric() {
        let mut set = prefix_chars.clone();
        set.insert(next);
        set
    } else if quantifier_at_allows_zero(pattern, token_end) {
        prefix_chars.clone()
    } else {
        BTreeSet::new()
    };
    (
        token_end + skip_quantifier_at(pattern, token_end),
        next_prefix,
    )
}

fn group_open_step(
    pattern: &[char],
    i: usize,
    prefix_chars: &BTreeSet<char>,
) -> (usize, BTreeSet<char>) {
    let starts_with_qcolon =
        pattern.len() >= i + 3 && pattern[i + 1] == '?' && pattern[i + 2] == ':';
    if starts_with_qcolon {
        return (i + 3, prefix_chars.clone());
    }
    if i + 1 < pattern.len() && pattern[i + 1] == '?' {
        let end_paren = pattern[i..].iter().position(|c| *c == ')').map(|o| i + o);
        let next_i = match end_paren {
            Some(end) => end + 1,
            None => i + 1,
        };
        return (next_i, BTreeSet::new());
    }
    (i + 1, BTreeSet::new())
}

fn step(pattern: &[char], i: usize, prefix_chars: &BTreeSet<char>) -> StepResult {
    let c = pattern[i];
    if c == '(' {
        let (next_i, next_prefix) = group_open_step(pattern, i, prefix_chars);
        return (next_i, next_prefix, None);
    }
    if PREFIX_RESET_CHARS.contains(c) {
        return (i + 1, BTreeSet::new(), None);
    }
    if c == '[' || c == '.' {
        return broad_scan_step(pattern, i, prefix_chars);
    }
    if c == '\\' && i + 1 < pattern.len() {
        let (next_i, next_prefix) = escape_step(pattern, i, prefix_chars);
        return (next_i, next_prefix, None);
    }
    let next_i = i + 1 + skip_quantifier_at(pattern, i + 1);
    let mut next_prefix = prefix_chars.clone();
    next_prefix.insert(c);
    (next_i, next_prefix, None)
}

/// Reference `_detect_unreachable_terminator_scan`.
#[must_use]
pub fn detect_unreachable_terminator_scan(pattern: &str) -> Option<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut prefix_chars: BTreeSet<char> = BTreeSet::new();
    let mut i = 0usize;
    while i < chars.len() {
        let (next_i, next_prefix, finding) = step(&chars, i, &prefix_chars);
        i = next_i;
        prefix_chars = next_prefix;
        if let Some(finding) = finding {
            return Some(finding);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminator_chars_returns_positive_char_classes() {
        let set = terminator_chars_at("[abc]", 0).expect("positive class");
        assert_eq!(set, BTreeSet::from(['a', 'b', 'c']));
    }

    #[test]
    fn terminator_chars_none_for_negated_and_empty_classes() {
        assert_eq!(terminator_chars_at("[^abc]", 0), None);
        assert_eq!(terminator_chars_at("[]", 0), None);
    }

    #[test]
    fn terminator_chars_none_past_the_end() {
        assert_eq!(terminator_chars_at("[abc]", 5), None);
    }

    #[test]
    fn terminator_chars_singleton_for_a_literal() {
        assert_eq!(terminator_chars_at("x", 0), Some(BTreeSet::from(['x'])));
    }

    #[test]
    fn terminator_chars_none_for_non_literal_leaders() {
        for leader in ["(", ")", "|", "^", "$", ".", "*", "+", "?", "{"] {
            assert_eq!(terminator_chars_at(leader, 0), None, "{leader}");
        }
    }

    #[test]
    fn terminator_chars_escaped_non_alnum_is_a_singleton() {
        assert_eq!(terminator_chars_at(r"\-", 0), Some(BTreeSet::from(['-'])));
        assert_eq!(terminator_chars_at(r"\d", 0), None);
    }

    #[test]
    fn detector_flags_a_scan_whose_terminator_the_prefix_cannot_reach() {
        assert_eq!(
            detect_unreachable_terminator_scan("a[^b]*c"),
            Some("[^b] preceded by a".to_owned())
        );
        // The dot span names the bare atom; the prefix set is sorted.
        assert_eq!(
            detect_unreachable_terminator_scan("foo.*bar"),
            Some(". preceded by fo".to_owned())
        );
        // Escaped non-alnum characters accumulate into the prefix.
        assert_eq!(
            detect_unreachable_terminator_scan(r"\$\([^)]+\)"),
            Some("[^)] preceded by $(".to_owned())
        );
    }

    #[test]
    fn detector_passes_when_the_terminator_is_reachable() {
        // The prefix itself is excluded, so the scan can absorb it.
        assert_eq!(detect_unreachable_terminator_scan("b[^b]*b"), None);
        assert_eq!(detect_unreachable_terminator_scan("[^a]*b"), None);
        assert_eq!(detect_unreachable_terminator_scan("a[^b]*$"), None);
        // The group close, not the tail literal, terminates the scan.
        assert_eq!(detect_unreachable_terminator_scan("a(?:x[^b]*)c"), None);
    }

    #[test]
    fn detector_tracks_prefixes_across_alternations() {
        // The first alternative already carries the finding.
        assert_eq!(
            detect_unreachable_terminator_scan("a[^b]*c|x[^b]*b"),
            Some("[^b] preceded by a".to_owned())
        );
    }

    #[test]
    fn quantifier_helpers_cover_the_brace_shapes() {
        let text: Vec<char> = "a{2,3}?b".chars().collect();
        assert_eq!(skip_brace_quantifier_at(&text, 1), 6);
        let text: Vec<char> = "a{2,x}b".chars().collect();
        assert_eq!(skip_brace_quantifier_at(&text, 1), 0);
        let text: Vec<char> = "a{,}b".chars().collect();
        assert_eq!(skip_brace_quantifier_at(&text, 1), 0);
        let text: Vec<char> = "a*?b".chars().collect();
        assert_eq!(skip_symbol_quantifier_at(&text, 1), 2);
    }

    #[test]
    fn quantifier_allows_zero_covers_star_question_and_braces() {
        let allows = |text: &str, k: usize| {
            quantifier_at_allows_zero(&text.chars().collect::<Vec<char>>(), k)
        };
        assert!(allows("a*b", 1));
        assert!(allows("a?b", 1));
        assert!(allows("a{0,3}b", 1));
        assert!(allows("a{,3}b", 1));
        assert!(!allows("a+b", 1));
        assert!(!allows("a{2,3}b", 1));
        assert!(!allows("ab", 1));
    }
}
