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
    if literal_chars.len() < 2 || !literal_chars.iter().all(|c| class_chars.contains(c)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantified_class_absorbs_the_following_literal() {
        assert_eq!(
            detect_ambiguous_literal_boundary(r"[a-z]*abc"),
            Some("[a-z]* then literal 'abc'".to_owned())
        );
        assert_eq!(
            detect_ambiguous_literal_boundary(r"[\w-]*--"),
            Some("[\\w-]* then literal '--'".to_owned())
        );
    }

    #[test]
    fn single_char_literals_are_not_ambiguous() {
        assert_eq!(detect_ambiguous_literal_boundary(r"[a-z]*x"), None);
    }

    #[test]
    fn literals_outside_the_class_are_not_absorbed() {
        assert_eq!(detect_ambiguous_literal_boundary(r"[0-9]*abc"), None);
    }

    #[test]
    fn unquantified_classes_never_absorb() {
        assert_eq!(detect_ambiguous_literal_boundary(r"[a-z]abc"), None);
    }

    #[test]
    fn unrepresentable_classes_are_skipped() {
        // An empty class body cannot absorb anything.
        assert_eq!(detect_ambiguous_literal_boundary("[]ab"), None);
    }

    #[test]
    fn the_detector_scans_every_class_in_the_pattern() {
        assert_eq!(
            detect_ambiguous_literal_boundary(r"prefix[\w.]*env"),
            Some("[\\w.]* then literal 'env'".to_owned())
        );
    }
}
