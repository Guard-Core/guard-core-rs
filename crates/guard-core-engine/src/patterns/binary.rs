//! Binary artifact density gate and binary-content heuristic, ported from
//! `guard_core/detection_engine/binary_prefix.py` and `semantic.py`
//! (`looks_like_binary_content`).
//!
//! String-model mapping: the reference scans decoded text where undecodable
//! bytes surface as surrogateescape code points (U+DC80..U+DCFF) and mojibake
//! as U+FFFD; both classes count as artifacts. The engine scans `&str` (always
//! valid UTF-8), so undecodable bytes never reach this module as surrogates;
//! the port's decode boundary represents them as U+FFFD (or drops them), which
//! is an artifact class here. The surrogate branch is kept for parity with the
//! reference class definition but is unreachable for `char`. All window
//! arithmetic runs on code-point indices, the same index space the corpus
//! mandates for threat positions.

/// Cumulative artifact-count prefix: `counts[i]` = artifacts in `s[..i]`.
/// Built over code points; indexing is by code-point index (the same space
/// the structural matchers and threat positions use).
#[must_use]
pub fn build_binary_prefix(text: &str) -> Vec<u32> {
    let mut counts = Vec::with_capacity(text.chars().count() + 1);
    counts.push(0u32);
    let mut count = 0u32;
    for c in text.chars() {
        if is_binary_artifact(c) {
            count += 1;
        }
        counts.push(count);
    }
    counts
}

const BINARY_DENSITY_RADIUS: usize = 64;
const BINARY_DENSITY_LIMIT: u32 = 4;

#[must_use]
pub fn match_is_binary_density(
    binary_prefix: &[u32],
    match_start: usize,
    match_end: usize,
) -> bool {
    if binary_prefix.is_empty() {
        return false;
    }
    let high = (match_end + BINARY_DENSITY_RADIUS).min(binary_prefix.len() - 1);
    let low = match_start.saturating_sub(BINARY_DENSITY_RADIUS);
    binary_prefix[high].saturating_sub(binary_prefix[low]) >= BINARY_DENSITY_LIMIT
}

#[must_use]
pub(crate) fn is_binary_artifact(c: char) -> bool {
    let cp = c as u32;
    // control characters (except tab/LF/CR) and DEL
    if (cp < 0x20 && !matches!(cp, 0x09 | 0x0A | 0x0D)) || cp == 0x7F {
        return true;
    }
    // replacement character
    if cp == 0xFFFD {
        return true;
    }
    #[cfg(not(coverage))] // unreachable: Rust chars exclude the surrogate
    // range, so the surrogateescape byte marks never appear as chars
    if (0xDC80..=0xDCFF).contains(&cp) {
        return true;
    }
    // Latin-1/Latin-Ext-A artifact, minus the text allowlist
    if (0x80..=0x024F).contains(&cp) {
        return !is_text_allowlist(c);
    }
    false
}

/// The only characters in `0x80..=0x024F` treated as text. Mirrors the
/// reference class complement exactly: within `0x80..=0xBF` only the
/// punctuation/marker singles are text, and all of `0xC0..=0xFF` (including
/// the multiplication and division signs) plus `0x100..=0x17F` are text.
#[must_use]
fn is_text_allowlist(c: char) -> bool {
    let cp = c as u32;
    if (0x00C0..=0x00FF).contains(&cp) {
        return true;
    }
    if matches!(
        cp,
        0x00A3 | 0x00A5 | 0x00AA | 0x00B0 | 0x00B1 | 0x00B2 | 0x00B3 | 0x00B5 | 0x00B9 | 0x00BA
    ) {
        return true;
    }
    (0x0100..=0x017F).contains(&cp)
}

const BINARY_CONTENT_RATIO_THRESHOLD: f64 = 0.2;

/// `looks_like_binary_content` from semantic.py.
#[must_use]
pub fn looks_like_binary_content(content: &str) -> bool {
    if content.is_empty() {
        return false;
    }
    let mut non_text = 0usize;
    let mut len = 0usize;
    for c in content.chars() {
        len += 1;
        let cp = c as u32;
        let is_ws = matches!(c, '\t' | '\r' | '\n');
        let printable = !c.is_control() && !matches!(cp, 0xFFFD);
        if !is_ws && (!printable || cp == 0xFFFD) {
            non_text += 1;
        }
    }
    let ratio = non_text as f64 / len as f64;
    ratio >= BINARY_CONTENT_RATIO_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_text_has_zero_artifacts() {
        let prefix = build_binary_prefix("hello <script> world\t\n");
        assert_eq!(prefix.last(), Some(&0));
    }

    #[test]
    fn control_bytes_count() {
        let prefix = build_binary_prefix("a\u{1}b\u{2}c\u{3}d\u{4}");
        assert!(match_is_binary_density(&prefix, 0, 8));
    }

    #[test]
    fn accented_text_is_allowed() {
        let prefix = build_binary_prefix("caf\u{00e9} cr\u{00e8}me br\u{00fb}l\u{00e9}");
        assert_eq!(prefix.last(), Some(&0));
    }

    #[test]
    fn artifact_classes_match_reference_exactly() {
        // The reference `_BINARY_ARTIFACT_RE` class set, collapsed to ranges
        // over the BMP ranges it covers (verified against guard-core 4.0.3).
        // Everything below 0x300 outside these ranges is text.
        const ARTIFACT_RANGES: &[(u32, u32)] = &[
            (0x00, 0x08),
            (0x0B, 0x0C),
            (0x0E, 0x1F),
            (0x7F, 0xA2),
            (0xA4, 0xA4),
            (0xA6, 0xA9),
            (0xAB, 0xAF),
            (0xB4, 0xB4),
            (0xB6, 0xB8),
            (0xBB, 0xBF),
            (0x0180, 0x024F),
        ];
        let is_ref_artifact = |cp: u32| {
            ARTIFACT_RANGES
                .iter()
                .any(|(lo, hi)| (*lo..=*hi).contains(&cp))
        };
        for cp in 0u32..=0x3000 {
            let c = char::from_u32(cp).expect("BMP scalar");
            assert_eq!(
                is_binary_artifact(c),
                is_ref_artifact(cp),
                "artifact mismatch at U+{cp:04X}"
            );
        }
    }

    #[test]
    fn latin1_punctuation_signs_are_text() {
        // U+00D7 (multiplication sign) and U+00F7 (division sign) sit in the
        // reference's text allowlist (all of 0xC0..=0xFF is text).
        let prefix = build_binary_prefix("3 \u{00d7} 4 \u{00f7} 2");
        assert_eq!(prefix.last(), Some(&0));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn density_gate_needs_a_prefix_and_enough_high_bytes() {
        // an empty prefix never gates
        assert!(!match_is_binary_density(&[], 0, 1));
        // fewer than the limit of high bytes in the window is fine
        let prefix = vec![0_u32, 0, 0, 0, 3, 3];
        assert!(!match_is_binary_density(&prefix, 2, 3));
        // a dense window gates
        let dense = vec![0_u32, 9, 9, 9, 9, 9];
        assert!(match_is_binary_density(&dense, 2, 3));
    }

    #[test]
    fn artifact_chars_cover_control_replacement_surrogate_and_latin() {
        assert!(is_binary_artifact('\u{1}'));
        assert!(is_binary_artifact('\u{7f}'));
        assert!(is_binary_artifact('\u{fffd}'));
        assert!(!is_binary_artifact(
            char::from_u32(0x0301).expect("in range")
        ));
        assert!(is_binary_artifact('\u{80}'));
        assert!(!is_binary_artifact('\t'));
        assert!(!is_binary_artifact('a'));
    }
}
