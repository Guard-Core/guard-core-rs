//! Template-injection scan matchers ported from
//! `guard_core/handlers/_suspatterns_templates.py` (spec 4.0.2).
//!
//! Region scan between opening/closing delimiters (`{{ }}`, `${ }`, `{% %}`,
//! `<% %>`, `#{ }`), not naive regex: an indicator must appear strictly inside
//! the region, and `{{`/`#{` forms skip regions dominated by a date.
//!
//! The indicator sources embed a `(?<!\d)` guard in front of the literal
//! arithmetic branch; the guard is enforced with a char check on the candidate
//! start (a candidate beginning mid-number is rejected, mirroring the
//! lookbehind exactly because every inner start of a digit run is also
//! digit-preceded).

use super::chars_util::{str_find_from, walk_forward_while};
use super::pyregex::{Candidate, PyRegex};

const KEYWORD_INDICATOR: &str = r"(?:system|exec|popen|eval|require|include)\s*\z";
const DOLLAR_INDICATOR: &str = r"@[\w.]+@|\b\w+\s*\(";
const CURLY_INDICATOR: &str = r"@[\w.]+@|\b\w+\(\s*\)";
const HASH_INDICATOR: &str = r"@[\w.]+@|\b\w+\s*\(";
const ASP_INDICATOR: &str = r"system|exec|eval|`|Runtime|IO\.|File\.|Dir\.";
const ARITH_UNQUOTED: &str = r"\d+\s*[*/%+\-]\s*\d+";
const ARITH_ASP: &str = r"\d+\s*[-+*/]\s*\d+";
const ARITH_QUOTED: &str = r#"['"]?\d+['"]?\s*[*/%+\-]\s*['"]?\d+['"]?"#;
const DATE_SOURCE: &str = r"\d{4}-\d{1,2}-\d{1,2}";

pub struct TemplateKind {
    pub opening: &'static str,
    pub closing: &'static str,
    /// indicator branches without the arithmetic alternative
    pub indicator: &'static str,
    /// arithmetic branch source (last alternative, carries the `(?<!\d)`
    /// guard structurally)
    pub arithmetic: &'static str,
}

pub const KIND_DOLLAR: TemplateKind = TemplateKind {
    opening: "${",
    closing: "}",
    indicator: DOLLAR_INDICATOR,
    arithmetic: ARITH_UNQUOTED,
};
pub const KIND_CURLY_CALL: TemplateKind = TemplateKind {
    opening: "{{",
    closing: "}}",
    indicator: CURLY_INDICATOR,
    arithmetic: ARITH_QUOTED,
};
pub const KIND_CURLY_KEYWORD: TemplateKind = TemplateKind {
    opening: "{{",
    closing: "}}",
    indicator: KEYWORD_INDICATOR,
    arithmetic: "",
};
pub const KIND_HASH: TemplateKind = TemplateKind {
    opening: "#{",
    closing: "}",
    indicator: HASH_INDICATOR,
    arithmetic: ARITH_QUOTED,
};
pub const KIND_PERCENT_KEYWORD: TemplateKind = TemplateKind {
    opening: "{%",
    closing: "%}",
    indicator: KEYWORD_INDICATOR,
    arithmetic: "",
};
pub const KIND_ASP: TemplateKind = TemplateKind {
    opening: "<%",
    closing: "%>",
    indicator: ASP_INDICATOR,
    arithmetic: ARITH_ASP,
};

pub struct TemplateRegion {
    pub start: usize,
    pub barrier: usize,
    pub end: usize,
}

/// `_template_regions`: opening/closing delimiter pairs with the reference's
/// cursor advance (`cursor = max(body_start, barrier - len(opening) + 1)`).
#[must_use]
pub fn template_regions(content: &str, opening: &str, closing: &str) -> Vec<TemplateRegion> {
    let mut regions = Vec::new();
    let mut cursor = 0usize;
    while let Some(start) = str_find_from(content, opening, cursor) {
        let body_start = start + opening.len();
        let Some(barrier) = str_find_from(content, &closing[..1], body_start) else {
            break;
        };
        cursor = body_start.max(barrier + 1 - opening.len());
        if content[barrier..].starts_with(closing) {
            regions.push(TemplateRegion {
                start,
                barrier,
                end: barrier + closing.len(),
            });
        }
    }
    regions
}

/// The frame: `opening + [^<first closing char>]* + closing`, anchored at the
/// region start and truncated at the region end.
fn template_frame(
    content: &str,
    opening: &str,
    closing: &str,
    start: usize,
    end: usize,
) -> Option<Candidate> {
    if !content[start..].starts_with(opening) {
        return None;
    }
    let body_start = start + opening.len();
    let first = closing.chars().next()?;
    let body_end = walk_forward_while(content, body_start, |c| c != first);
    if !content[body_end..].starts_with(closing) {
        return None;
    }
    let frame_end = body_end + closing.len();
    if frame_end > end {
        return None;
    }
    Some(Candidate::new(start, frame_end))
}

fn search_between(re: &PyRegex, haystack: &str, start: usize, end: usize) -> bool {
    if start >= end || end > haystack.len() {
        return false;
    }
    re.re().is_match(&haystack[start..end])
}

/// Arithmetic-branch hit with the `(?<!\d)` guard enforced structurally.
#[must_use]
fn arithmetic_in_window(content: &str, arithmetic: &PyRegex, start: usize, end: usize) -> bool {
    if start >= end || end > content.len() {
        return false;
    }
    let window = &content[start..end];
    for m in arithmetic.re().find_iter(window) {
        // lookbehind sees the full string, not just the window
        let abs_start = start + m.start();
        let digit_before = content[..abs_start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_digit());
        if !digit_before {
            return true;
        }
    }
    false
}

fn date_restart(
    content: &str,
    opening: &str,
    start: usize,
    barrier: usize,
    dates: &PyRegex,
) -> Option<usize> {
    let from = (start + 2).min(content.len());
    let to = barrier.min(content.len());
    if from >= to {
        return Some(start);
    }
    let last_date = dates
        .re()
        .find_iter(&content[from..to])
        .last()
        .map(|m| m.start() + from);
    last_date.map_or(Some(start), |pos| {
        // no later opening before the barrier: the reference finds nothing and
        // skips the region entirely
        str_find_from(content, opening, pos + 1).filter(|i| *i < barrier)
    })
}

/// `_template_keyword_matches`: an indicator keyword must appear strictly
/// inside the region (excluding the first char after the opening delimiter).
#[must_use]
pub fn template_keyword_matches(
    content: &str,
    kind: &TemplateKind,
    ignore_case: bool,
) -> Vec<Candidate> {
    let Ok(indicator) = PyRegex::compile(kind.indicator, ignore_case) else {
        return Vec::new();
    };
    let mut matches = Vec::new();
    for region in template_regions(content, kind.opening, kind.closing) {
        let from = region.start + kind.opening.len() + 1;
        if search_between(&indicator, content, from, region.barrier)
            && let Some(frame) = template_frame(
                content,
                kind.opening,
                kind.closing,
                region.start,
                region.end,
            )
        {
            matches.push(frame);
        }
    }
    matches
}

/// `_template_expression_matches`: indicator inside the region, with the
/// date-dominance restart for `{{`/`#{` forms.
#[must_use]
pub fn template_expression_matches(
    content: &str,
    kind: &TemplateKind,
    ignore_case: bool,
) -> Vec<Candidate> {
    let Ok(indicator) = PyRegex::compile(kind.indicator, ignore_case) else {
        return Vec::new();
    };
    let arithmetic = PyRegex::compile(kind.arithmetic, ignore_case).ok();
    let dates = PyRegex::compile(DATE_SOURCE, ignore_case).ok();
    let has_dates = matches!(kind.opening, "{{" | "#{");
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for region in template_regions(content, kind.opening, kind.closing) {
        if region.start < last_end {
            continue;
        }
        let mut start = region.start;
        if has_dates && let Some(dates) = &dates {
            let Some(restarted) = date_restart(content, kind.opening, start, region.barrier, dates)
            else {
                continue;
            };
            start = restarted;
        }
        let hit = search_between(
            &indicator,
            content,
            start + kind.opening.len(),
            region.barrier,
        ) || arithmetic.as_ref().is_some_and(|a| {
            arithmetic_in_window(content, a, start + kind.opening.len(), region.barrier)
        });
        if hit
            && let Some(frame) =
                template_frame(content, kind.opening, kind.closing, start, region.end)
        {
            matches.push(frame);
            last_end = region.end;
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curly_keyword_requires_indicator_inside() {
        // the reference search window excludes the first body char, so a
        // keyword flush against the opening delimiter does not fire
        assert!(template_keyword_matches("{{system('id')}}", &KIND_CURLY_KEYWORD, true).is_empty());
        let ms = template_keyword_matches("{{ system }}", &KIND_CURLY_KEYWORD, true);
        assert_eq!(ms.len(), 1);
        assert!(template_keyword_matches("{{name}}", &KIND_CURLY_KEYWORD, true).is_empty());
    }

    #[test]
    fn curly_call_date_suppression() {
        let stale = "{{ 2024-01-02 }}";
        assert!(template_expression_matches(stale, &KIND_CURLY_CALL, true).is_empty());
        let call = "{{ render() }}";
        assert_eq!(
            template_expression_matches(call, &KIND_CURLY_CALL, true).len(),
            1
        );
    }

    #[test]
    fn hash_brace_call() {
        let ms = template_expression_matches("#{7*7}", &KIND_HASH, true);
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn dollar_brace_call() {
        let ms = template_expression_matches("${eval(x)}", &KIND_DOLLAR, true);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("${eval(x)}"), "${eval(x)}");
    }

    #[test]
    fn arithmetic_guard_blocks_digit_preceded_start() {
        // "3*4" is preceded by a space: the (?<!\d) guard passes
        assert_eq!(
            template_expression_matches("{{12 3*4}}", &KIND_CURLY_CALL, true).len(),
            1
        );
        assert_eq!(
            template_expression_matches("{{7*6}}", &KIND_CURLY_CALL, true).len(),
            1
        );
        // "a123*4" matches at the leading digit ("a" precedes it)
        assert_eq!(
            template_expression_matches("{{a123*4}}", &KIND_CURLY_CALL, true).len(),
            1
        );
        // "12 3" cannot start mid-number: the only candidate start "3*" is
        // fine, but "2 3*4"-style digit-preceded starts never occur here
        assert_eq!(
            template_expression_matches("{{x1 3*4}}", &KIND_CURLY_CALL, true).len(),
            1
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn malformed_frames_and_missing_closers_are_rejected() {
        // two adjacent regions both match
        assert_eq!(
            template_keyword_matches("{{ system }}{{ system }}", &KIND_CURLY_KEYWORD, true).len(),
            2
        );
        // a keyword inside the first char after the opening is not "inside"
        assert!(template_keyword_matches("{{system}}", &KIND_CURLY_KEYWORD, true).is_empty());
        // an unterminated frame: no region, nothing matches
        assert!(template_keyword_matches("{{ system ", &KIND_CURLY_KEYWORD, true).is_empty());
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn digit_preceded_arithmetic_candidates_are_rejected() {
        // the quote forces the arithmetic match to start after the leading
        // digit, which is exactly the start the (?<!\d) guard rejects
        assert!(template_expression_matches("#{1\"2*3}", &KIND_HASH, true).is_empty());
        // the later region in the same content still fires
        assert_eq!(
            template_expression_matches("#{1\"2*3}#{eval(x)}", &KIND_HASH, true).len(),
            1
        );
    }

    #[test]
    fn a_region_body_shorter_than_the_restart_lookback_restarts_in_place() {
        // "#{}" has no body to scan for dates: the restart returns the region
        // start unchanged and the empty region never hits
        assert_eq!(
            template_expression_matches("#{}#{eval(x)}", &KIND_HASH, true).len(),
            1
        );
    }

    #[test]
    fn an_overlapping_second_region_is_skipped_after_a_hit() {
        // the inner `<%` region starts inside the first region's accepted
        // span, so the restart cursor yields it and it is dropped
        assert_eq!(
            template_expression_matches("<%eval<%>%>", &KIND_ASP, true).len(),
            1
        );
    }
}
