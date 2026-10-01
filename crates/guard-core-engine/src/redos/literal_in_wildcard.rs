//! Quantified-class literal absorption detection.
//!
//! Port of the reference `_redos_literal_in_wildcard.py`.

use super::ambiguous_tail::atom_char_set;
use super::structure::{outer_quantifier_len, skip_char_class};

fn literal_run_at(pattern: &[char], i: usize) -> (String, usize) {
    let mut j = i;
    let n = pattern.len();
    while j < n && (pattern[j].is_alphanumeric() || pattern[j] == '-') {
        j += 1;
    }
    (pattern[i..j].iter().collect(), j)
}

fn wildcard_absorbs_literal(pattern: &[char], i: usize, end: usize) -> Option<String> {
    let qlen = outer_quantifier_len(pattern, end);
    if qlen == 0 {
        return None;
    }
    let class_atom: String = pattern[i..end].iter().collect();
    let class_chars = atom_char_set(&class_atom);
    if class_chars.is_empty() {
        return None;
    }
    let (literal, _literal_end) = literal_run_at(pattern, end + qlen);
    let literal_chars: Vec<char> = literal.chars().collect();
    if literal_chars.len() < 2
        || !literal_chars.iter().all(|c| class_chars.contains(c))
    {
        return None;
    }
    let quantified: String = pattern[i..end + qlen].iter().collect();
    Some(format!("{quantified} then literal '{literal}'"))
}

/// Reference `_detect_ambiguous_literal_boundary`.
#[must_use]
pub fn detect_ambiguous_literal_boundary(pattern: &str) -> Option<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0usize;
    let n = chars.len();
    while i < n {
        if chars[i] != '[' {
            i += 1;
            continue;
        }
        let end = skip_char_class(&chars, i);
        if let Some(finding) = wildcard_absorbs_literal(&chars, i, end) {
            return Some(finding);
        }
        i = end;
    }
    None
}
