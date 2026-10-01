//! Bounded scan windows ported from `guard_core/detection_engine/scan_window.py`
//! (spec 4.0.2).
//!
//! Several built-in detection patterns have the shape
//! `literal_prefix + unbounded_negated_class + terminator`. When the
//! terminator is absent, the regex engine rescans to end-of-input from every
//! prefix occurrence, which is quadratic in input length. This module locates
//! prefix and terminator occurrences with linear passes, then runs the
//! caller's UNMODIFIED pattern against a bounded span per prefix candidate:
//! from that candidate to the rightmost terminator occurrence reachable from
//! it. The pattern itself is never rewritten.

use regex::Regex;

use super::pyregex::{Candidate, PyRegex};

/// Python `pattern.match(text, start, end)`: anchored at `start`, the string
/// effectively truncated at `end`.
fn match_span(re: &Regex, haystack: &str, start: usize, end: usize) -> Option<Candidate> {
    if start > end {
        return None;
    }
    let truncated = &haystack[..end];
    let m = re.find_at(truncated, start)?;
    if m.start() != start {
        return None;
    }
    Some(Candidate::new(m.start(), m.end()))
}

#[must_use]
pub fn bounded_finditer(
    haystack: &str,
    compiled: &PyRegex,
    prefix: &PyRegex,
    terminator: &PyRegex,
) -> Vec<Candidate> {
    bounded_finditer_guarded(haystack, compiled, prefix, terminator, |_, _| true)
}

/// `bounded_finditer` with a per-candidate guard (the reference runs the
/// UNMODIFIED pattern inside the window; a guard failure abandons the prefix
/// candidate exactly like a failed window match).
#[must_use]
pub fn bounded_finditer_guarded(
    haystack: &str,
    compiled: &PyRegex,
    prefix: &PyRegex,
    terminator: &PyRegex,
    guard: impl Fn(&str, Candidate) -> bool,
) -> Vec<Candidate> {
    let terminator_ends: Vec<usize> = terminator
        .re()
        .find_iter(haystack)
        .map(|m| m.end())
        .collect();
    if terminator_ends.is_empty() {
        return Vec::new();
    }
    let ceiling = terminator_ends[terminator_ends.len() - 1];

    let prefix_starts: Vec<usize> = prefix.re().find_iter(haystack).map(|m| m.start()).collect();
    if prefix_starts.is_empty() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let mut search_from = 0;
    let mut start_index = 0;
    loop {
        while start_index < prefix_starts.len() && prefix_starts[start_index] < search_from {
            start_index += 1;
        }
        let mut found: Option<Candidate> = None;
        for (offset, &start) in prefix_starts.iter().enumerate().skip(start_index) {
            if start >= ceiling {
                break;
            }
            if let Some(m) = match_span(compiled.re(), haystack, start, ceiling)
                && guard(haystack, m)
            {
                start_index = offset;
                found = Some(m);
                break;
            }
        }
        let Some(m) = found else {
            return matches;
        };
        matches.push(m);
        search_from = if m.end > m.start { m.end } else { m.start + 1 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_matches_inside_window() {
        let compiled = PyRegex::compile(r"<script[^>]*>[^<]*<\/script\s*>", false).unwrap();
        let prefix = PyRegex::compile("<script", false).unwrap();
        let terminator = PyRegex::compile(r"<\/script\s*>", false).unwrap();
        let text = "junk <script>a</script> tail <script>b</script>";
        let ms = bounded_finditer(text, &compiled, &prefix, &terminator);
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].text(text), "<script>a</script>");
        assert_eq!(ms[1].text(text), "<script>b</script>");
    }

    #[test]
    fn no_terminator_no_match() {
        let compiled = PyRegex::compile(r"<script[^>]*>[^<]*<\/script\s*>", false).unwrap();
        let prefix = PyRegex::compile("<script", false).unwrap();
        let terminator = PyRegex::compile(r"<\/script\s*>", false).unwrap();
        assert!(bounded_finditer("<script>a", &compiled, &prefix, &terminator).is_empty());
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn bounded_finditer_returns_nothing_when_the_prefix_is_absent() {
        let compiled =
            crate::patterns::pyregex::PyRegex::compile(r"<script[^>]*>x</script>", false).unwrap();
        let prefix = crate::patterns::pyregex::PyRegex::compile("<script", false).unwrap();
        let terminator =
            crate::patterns::pyregex::PyRegex::compile(r"<\/script\s*>", false).unwrap();
        // the terminator exists but no prefix anywhere: nothing matches
        assert!(bounded_finditer("tail </script>", &compiled, &prefix, &terminator).is_empty());
    }

    #[test]
    fn a_prefix_position_the_window_cannot_anchor_is_abandoned() {
        let compiled = PyRegex::compile(r"<script[^>]*>[^<]*<\/script\s*>", false).unwrap();
        let prefix = PyRegex::compile("<script", false).unwrap();
        let terminator = PyRegex::compile(r"<\/script\s*>", false).unwrap();
        // the first prefix occurrence is followed by `a</b>` before any `>`:
        // the window pattern cannot anchor there and the position is dropped
        let text = "<script>a</b> <script>b</script>";
        let ms = bounded_finditer(text, &compiled, &prefix, &terminator);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text(text), "<script>b</script>");
    }

    #[test]
    fn a_prefix_window_that_cannot_complete_returns_none_and_is_abandoned() {
        let compiled = PyRegex::compile(r"<script[^>]*>[^<]*<\/script\s*>", false).unwrap();
        let prefix = PyRegex::compile("<script", false).unwrap();
        let terminator = PyRegex::compile(r"<\/script\s*>", false).unwrap();
        // The `b` element breaks the `[^<]*` run before the ceiling, so
        // `find_at` inside the truncated window finds nothing.
        let text = "<script><b></script> tail";
        assert!(bounded_finditer(text, &compiled, &prefix, &terminator).is_empty());
    }

    #[test]
    fn a_zero_width_window_match_advances_one_char() {
        // `z*` matches the empty string at the prefix position: the scan
        // must step forward instead of looping in place.
        let compiled = PyRegex::compile("z*", false).unwrap();
        let prefix = PyRegex::compile("x", false).unwrap();
        let terminator = PyRegex::compile("b", false).unwrap();
        let ms = bounded_finditer("xb", &compiled, &prefix, &terminator);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 0);
        assert_eq!(ms[0].end, 0);
    }

    #[test]
    fn prefix_candidates_at_or_past_the_last_terminator_are_skipped() {
        let compiled = PyRegex::compile(r"<script[^>]*>[^<]*<\/script\s*>", false).unwrap();
        let prefix = PyRegex::compile("<script", false).unwrap();
        let terminator = PyRegex::compile(r"<\/script\s*>", false).unwrap();
        // the trailing `<script>` sits beyond the last terminator end
        let text = "<script>a</script> tail <script>";
        let ms = bounded_finditer(text, &compiled, &prefix, &terminator);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text(text), "<script>a</script>");
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;
    use crate::patterns::pyregex::PyRegex;

    #[test]
    fn an_inverted_window_is_never_anchored() {
        // `start > end` truncates to an empty (inverted) span: no anchor
        let re = PyRegex::compile(r"a", false).unwrap();
        assert!(match_span(re.re(), "abc", 2, 1).is_none());
    }
}
