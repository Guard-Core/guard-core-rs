//! Adversarial literal run extraction.
//!
//! Port of the reference `_redos_literal_runs.py`: walk the pattern and
//! flush maximal runs of literal characters a probe can repeat, resetting
//! at quantifier boundaries, groups, and hard meta characters.

use super::ambiguous_tail::atom_char_set;
use super::structure::{find_group_end, skip_char_class};

const ADVERSARIAL_RUN_HARD_RESET_CHARS: &str = "|^$.";
const ADVERSARIAL_RUN_NARROW_CLASS_MAX_CHARS: usize = 10;

fn flush_run(runs: &mut Vec<String>, current: &mut Vec<char>) {
    if !current.is_empty() {
        runs.push(current.iter().collect());
        current.clear();
    }
}

fn skip_lazy_marker(text: &[char], k: usize) -> usize {
    if k < text.len() && text[k] == '?' {
        k + 1
    } else {
        k
    }
}

fn brace_quantifier_span_allows_zero(text: &[char], k: usize) -> (usize, bool) {
    let Some(offset) = text[k..].iter().position(|c| *c == '}') else {
        return (k, false);
    };
    let end_brace = k + offset;
    let inner: String = text[k + 1..end_brace].iter().collect();
    let low = inner.split(',').next().unwrap_or("");
    if !low.is_empty() && !low.chars().all(|c| c.is_ascii_digit()) {
        return (k, false);
    }
    let end = skip_lazy_marker(text, end_brace + 1);
    (end, low.is_empty() || low == "0")
}

fn quantifier_span_allows_zero(text: &[char], k: usize) -> (usize, bool) {
    if k >= text.len() {
        return (k, false);
    }
    match text[k] {
        '*' | '?' => (skip_lazy_marker(text, k + 1), true),
        '+' => (skip_lazy_marker(text, k + 1), false),
        '{' => brace_quantifier_span_allows_zero(text, k),
        _ => (k, false),
    }
}

fn char_class_step(
    pattern: &[char],
    i: usize,
    runs: &mut Vec<String>,
    current: &mut Vec<char>,
) -> usize {
    let end = skip_char_class(pattern, i);
    let class_text: String = pattern[i..end].iter().collect();
    let mut chars = atom_char_set(&class_text);
    chars.sort();
    if !chars.is_empty() && chars.len() <= ADVERSARIAL_RUN_NARROW_CLASS_MAX_CHARS {
        current.push(chars[0]);
    } else {
        flush_run(runs, current);
    }
    end
}

fn group_open_step(
    pattern: &[char],
    i: usize,
    n: usize,
    runs: &mut Vec<String>,
    current: &mut Vec<char>,
    stack: &mut Vec<bool>,
) -> usize {
    let transparent = pattern.len() >= i + 3
        && pattern[i + 1] == '?'
        && pattern[i + 2] == ':';
    if transparent {
        stack.push(true);
        return i + 3;
    }
    if i + 1 < n && pattern[i + 1] == '?' {
        flush_run(runs, current);
        let end_paren = find_group_end(pattern, i);
        return end_paren.unwrap_or(i + 1);
    }
    stack.push(false);
    flush_run(runs, current);
    i + 1
}

fn escape_step(
    pattern: &[char],
    i: usize,
    runs: &mut Vec<String>,
    current: &mut Vec<char>,
) -> usize {
    let next = pattern[i + 1];
    let token_end = i + 2;
    if next.is_alphanumeric() {
        let (qend, allows_zero) = quantifier_span_allows_zero(pattern, token_end);
        if allows_zero {
            return qend;
        }
        flush_run(runs, current);
        return if qend > token_end { qend } else { token_end };
    }
    current.push(next);
    token_end
}

fn step(
    pattern: &[char],
    i: usize,
    n: usize,
    runs: &mut Vec<String>,
    current: &mut Vec<char>,
    stack: &mut Vec<bool>,
) -> usize {
    let c = pattern[i];
    if c == '[' {
        return char_class_step(pattern, i, runs, current);
    }
    if c == '(' {
        return group_open_step(pattern, i, n, runs, current, stack);
    }
    if c == ')' {
        let transparent = stack.pop().unwrap_or(false);
        if !transparent {
            flush_run(runs, current);
        }
        return i + 1;
    }
    if ADVERSARIAL_RUN_HARD_RESET_CHARS.contains(c) {
        flush_run(runs, current);
        return i + 1;
    }
    if matches!(c, '*' | '+' | '?') {
        return i + 1;
    }
    if c == '{' {
        let end_brace = pattern[i..].iter().position(|closed| *closed == '}');
        return match end_brace {
            Some(offset) => i + offset + 1,
            None => i + 1,
        };
    }
    if c == '\\' && i + 1 < n {
        return escape_step(pattern, i, runs, current);
    }
    current.push(c);
    i + 1
}

/// Reference `_adversarial_literal_runs`.
#[must_use]
pub fn adversarial_literal_runs(pattern: &str) -> Vec<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    let mut runs: Vec<String> = Vec::new();
    let mut current: Vec<char> = Vec::new();
    let mut stack: Vec<bool> = Vec::new();
    let mut i = 0usize;
    while i < n {
        i = step(&chars, i, n, &mut runs, &mut current, &mut stack);
    }
    flush_run(&mut runs, &mut current);
    runs.into_iter().filter(|run| !run.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_quantifier_span_allows_zero_branches() {
        let cases: Vec<(&str, usize, (usize, bool))> = vec![
            ("a{3", 1, (1, false)),
            ("a{x,3}b", 1, (1, false)),
            ("a{3}b", 1, (4, false)),
            ("a{0,3}b", 1, (6, true)),
            ("a{,3}b", 1, (5, true)),
            ("a{3}?b", 1, (5, false)),
        ];
        for (text, k, expected) in cases {
            assert_eq!(
                brace_quantifier_span_allows_zero(&text.chars().collect::<Vec<char>>(), k),
                expected,
                "text {text:?}"
            );
        }
    }

    #[test]
    fn quantifier_span_allows_zero_shapes() {
        let allows = |text: &str, k: usize| {
            quantifier_span_allows_zero(&text.chars().collect::<Vec<char>>(), k)
        };
        assert_eq!(allows("a*b", 1), (2, true));
        assert_eq!(allows("a+b", 1), (2, false));
        assert_eq!(allows("ab", 1), (1, false));
    }

    #[test]
    fn escaped_non_alnum_characters_join_the_run() {
        assert_eq!(adversarial_literal_runs(r"\."), vec![".".to_owned()]);
    }

    #[test]
    fn required_classes_separate_words() {
        assert_eq!(
            adversarial_literal_runs(r"prefix\dsuffix"),
            vec!["prefix".to_owned(), "suffix".to_owned()]
        );
    }

    #[test]
    fn zero_width_quantified_escapes_keep_the_run_going() {
        assert_eq!(
            adversarial_literal_runs(r"ab\dc"),
            vec!["ab".to_owned(), "c".to_owned()]
        );
    }

    #[test]
    fn groups_and_hard_resets_flush_runs() {
        assert_eq!(
            adversarial_literal_runs("ab|cd"),
            vec!["ab".to_owned(), "cd".to_owned()]
        );
        // Closing a capturing group flushes; a transparent group does not.
        assert_eq!(
            adversarial_literal_runs("(ab)cd"),
            vec!["ab".to_owned(), "cd".to_owned()]
        );
        assert_eq!(
            adversarial_literal_runs("(?:ab)cd"),
            vec!["abcd".to_owned()]
        );
        assert_eq!(
            adversarial_literal_runs(r"a\.b"),
            vec!["a.b".to_owned()]
        );
    }

    #[test]
    fn quantifier_markers_are_skipped_without_flushing() {
        assert_eq!(adversarial_literal_runs("ab*cd"), vec!["abcd"]);
        assert_eq!(adversarial_literal_runs("ab{2}cd"), vec!["abcd"]);
        // An unterminated brace still skips only the brace itself.
        assert_eq!(adversarial_literal_runs("ab{2"), vec!["ab2"]);
    }

    #[test]
    fn narrow_char_classes_contribute_their_first_char() {
        assert_eq!(
            adversarial_literal_runs("[ab]x"),
            vec!["ax".to_owned()]
        );
        // Wide or negated classes flush instead.
        assert_eq!(adversarial_literal_runs("[a-z]x"), vec!["x".to_owned()]);
    }

    #[test]
    fn skip_lazy_marker_only_consumes_a_question_mark() {
        let text: Vec<char> = "a?b".chars().collect();
        assert_eq!(skip_lazy_marker(&text, 1), 2);
        assert_eq!(skip_lazy_marker(&text, 0), 0);
    }
}
