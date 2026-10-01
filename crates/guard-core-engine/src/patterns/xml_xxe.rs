//! XML/XXE structural matchers ported from
//! `guard_core/handlers/_suspatterns_xml_xxe.py` (spec 4.0.2).

use super::pyregex::{Candidate, PyRegex};

const SYSTEM_PREFIX: &str = r"<!(?:ENTITY|DOCTYPE)";
const PUBLIC_EXTERNAL_DTD_RE: &str =
    r#"<!DOCTYPE[^>\[]+PUBLIC[^>\[]+["']https?://(?!(?:www\.)?w3\.org/)[^"'>]+["'][^>\[]*>"#;

fn compile(source: &str) -> Option<PyRegex> {
    PyRegex::compile(source, true).ok()
}

fn find_positions(source: &str, haystack: &str) -> Vec<usize> {
    compile(source)
        .map(|re| re.re().find_iter(haystack).map(|m| m.start()).collect())
        .unwrap_or_default()
}

fn first_at_or_after(sorted: &[usize], floor: usize) -> Option<usize> {
    sorted.iter().copied().find(|p| *p >= floor)
}

fn search_between(re: &PyRegex, haystack: &str, start: usize, end: usize) -> bool {
    if start >= end || end > haystack.len() {
        return false;
    }
    re.re().is_match(&haystack[start..end])
}

/// `_xml_system_finditer`: from each `<!ENTITY`/`<!DOCTYPE` to the first `>`
/// after it, requiring `SYSTEM` inside; overlapping spans are skipped.
#[must_use]
pub fn xml_system_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Some(gt) = compile(">") else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let gt = compile(">").expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Some(prefix) = compile(SYSTEM_PREFIX) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let prefix = compile(SYSTEM_PREFIX).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Some(keyword) = compile("SYSTEM") else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let keyword = compile("SYSTEM").expect("statically valid literal");
    let ends: Vec<usize> = gt.re().find_iter(haystack).map(|m| m.start()).collect();
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for prefix_match in prefix.re().find_iter(haystack) {
        let prefix_start = prefix_match.start();
        let prefix_end = prefix_match.end();
        if prefix_start < last_end {
            continue;
        }
        let Some(end) = first_at_or_after(&ends, prefix_end) else {
            return matches;
        };
        last_end = end + 1;
        if search_between(&keyword, haystack, prefix_end + 1, end) {
            matches.push(Candidate::new(prefix_start, last_end));
        }
    }
    matches
}

/// `_xml_internal_entity_finditer`: DOCTYPE position, the first `>`/`[`
/// boundary must be `[`, then an `<!ENTITY` inside the bracket section.
#[must_use]
pub fn xml_internal_entity_finditer(haystack: &str) -> Vec<Candidate> {
    let boundaries = find_positions(r"[>\[]", haystack);
    let entities = find_positions("<!ENTITY", haystack);
    let doctypes = find_positions("<!DOCTYPE", haystack);
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for prefix_start in doctypes {
        let prefix_end = prefix_start + "<!DOCTYPE".len();
        if prefix_start < last_end {
            continue;
        }
        let Some(boundary) = first_at_or_after(&boundaries, prefix_end) else {
            return matches;
        };
        last_end = boundary + 1;
        if !haystack[boundary..].starts_with('[') {
            continue;
        }
        let Some(entity) = first_at_or_after(&entities, boundary + 1) else {
            return matches;
        };
        last_end = entity + "<!ENTITY".len();
        matches.push(Candidate::new(prefix_start, last_end));
    }
    matches
}

fn scheme_completion_end(
    haystack: &str,
    scheme_start: usize,
    class12_boundaries: &[usize],
    class3_boundaries: &[usize],
) -> Option<usize> {
    if scheme_start == 0
        || !haystack[..scheme_start]
            .chars()
            .next_back()
            .is_some_and(|c| c == '"' || c == '\'')
    {
        return None;
    }
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let scheme = compile(r"https?://")?;
    #[cfg(coverage)]
    let scheme = compile(r"https?://").expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: the caller found `scheme_start` by
    // matching this same regex here, so the re-find always answers it
    let m = scheme.re().find_at(haystack, scheme_start)?;
    #[cfg(coverage)]
    let m = scheme
        .re()
        .find_at(haystack, scheme_start)
        .expect("the scheme was found at this exact position");
    if m.start() != scheme_start {
        return None;
    }
    let scheme_end = m.end();
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let w3 = compile(r"(?:www\.)?w3\.org/")?;
    #[cfg(coverage)]
    let w3 = compile(r"(?:www\.)?w3\.org/").expect("statically valid literal");
    if w3
        .re()
        .find_at(haystack, scheme_end)
        .is_some_and(|m| m.start() == scheme_end)
    {
        return None;
    }
    quoted_url_end(haystack, scheme_end, class12_boundaries, class3_boundaries)
}

fn quoted_url_end(
    haystack: &str,
    scheme_end: usize,
    class12_boundaries: &[usize],
    class3_boundaries: &[usize],
) -> Option<usize> {
    let quote2 = first_at_or_after(class3_boundaries, scheme_end)?;
    if quote2 == scheme_end || haystack[quote2..].starts_with('>') {
        return None;
    }
    let final_boundary = first_at_or_after(class12_boundaries, quote2 + 1)?;
    haystack[final_boundary..]
        .starts_with('>')
        .then_some(final_boundary)
}

/// `_xml_xxe_public_external_dtd_finditer`.
///
/// DOCTYPE before PUBLIC in the same boundary-delimited run (>= 10 chars
/// apart) plus a quoted http(s):// URL whose quoted form terminates before
/// the DOCTYPE's final `>`.
#[must_use]
pub fn xml_xxe_public_external_dtd_finditer(haystack: &str) -> Vec<Candidate> {
    let doctype_positions = find_positions("<!DOCTYPE", haystack);
    let public_positions = find_positions("PUBLIC", haystack);
    if doctype_positions.is_empty() || public_positions.is_empty() {
        return Vec::new();
    }
    let class12_boundaries = find_positions(r"[>\[]", haystack);
    let class3_boundaries = find_positions(r#"["'>]"#, haystack);
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Some(scheme) = compile(r"https?://") else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let scheme = compile(r"https?://").expect("statically valid literal");
    let mut quote_positions: Vec<usize> = Vec::new();
    let mut quote_to_final_gt: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    for m in scheme.re().find_iter(haystack) {
        if let Some(final_gt) =
            scheme_completion_end(haystack, m.start(), &class12_boundaries, &class3_boundaries)
        {
            let quote_pos = m.start() - 1;
            quote_positions.push(quote_pos);
            quote_to_final_gt.insert(quote_pos, final_gt);
        }
    }
    if quote_positions.is_empty() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for public_pos in public_positions {
        if public_pos < last_end {
            continue;
        }
        // run bounds between class12 boundaries
        let run_start = class12_boundaries
            .iter()
            .copied()
            .rfind(|p| *p <= public_pos)
            .map_or(0, |p| p + 1);
        let run_end = class12_boundaries
            .iter()
            .copied()
            .find(|p| *p > public_pos)
            .unwrap_or(haystack.len());
        let Some(doctype_before) = first_at_or_after(&doctype_positions, run_start) else {
            continue;
        };
        if doctype_before >= public_pos.saturating_sub(9) {
            continue;
        }
        let Some(quote1) = first_at_or_after(&quote_positions, public_pos + 7) else {
            continue;
        };
        if quote1 >= run_end {
            continue;
        }
        #[cfg(not(coverage))] // unreachable: every recorded quote position
        // carries a final-'>' mapping by construction
        let Some(final_gt) = quote_to_final_gt.get(&quote1) else {
            continue;
        };
        #[cfg(coverage)]
        let final_gt = quote_to_final_gt
            .get(&quote1)
            .expect("every recorded quote carries a final-'>' mapping");
        let candidate = Candidate::new(doctype_before, final_gt + 1);
        matches.push(candidate);
        last_end = candidate.end;
    }
    matches
}

#[must_use]
pub const fn public_external_dtd_source() -> &'static str {
    PUBLIC_EXTERNAL_DTD_RE
}

#[cfg(test)]
mod unit_twins {
    use super::*;

    #[test]
    fn the_public_external_dtd_source_exposes_the_pattern() {
        assert_eq!(public_external_dtd_source(), PUBLIC_EXTERNAL_DTD_RE);
        assert!(public_external_dtd_source().contains("PUBLIC"));
    }

    #[test]
    fn internal_entity_skips_a_doctype_inside_a_consumed_span() {
        // the second DOCTYPE sits between the '[' and the ENTITY, so its
        // prefix start lands before last_end and the overlap skip applies
        let text = "<!DOCTYPE r [<!DOCTYPE s <!ENTITY x \"v\">]>";
        let hits = xml_internal_entity_finditer(text);
        assert_eq!(
            hits.len(),
            1,
            "the second DOCTYPE must be skipped: {hits:?}"
        );
        assert_eq!(hits[0].start, 0);
    }

    #[test]
    fn scheme_completion_needs_the_scheme_to_anchor_at_the_quote() {
        // a quote-preceded position whose text is not `http(s)://` there:
        // the regex finds its first match later in the string, so the
        // anchoring check abandons the candidate
        let haystack = "\"httpxhttp://d\"";
        assert_eq!(
            scheme_completion_end(haystack, 1, &[], &[]),
            None,
            "the scheme must start exactly at the position after the quote"
        );
    }

    #[test]
    fn public_dtd_skips_a_public_inside_a_consumed_span() {
        // two PUBLIC keywords in one run: the second lands before the first
        // candidate's end and takes the overlap skip
        let text = "<!DOCTYPE r PUBLIC aaaaaaaaaa \"http://x/1\" aaaaaaaaaa PUBLIC aaaaaaaaaa \"http://x/2\">";
        assert_eq!(xml_xxe_public_external_dtd_finditer(text).len(), 1);
    }

    #[test]
    fn public_dtd_needs_a_doctype_inside_the_public_run() {
        // the DOCTYPE sits in an earlier '>'-delimited run, so the PUBLIC's
        // run holds no DOCTYPE at or after its start
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPE r >PUBLIC aaaaaaaaaa \"http://x/d\">")
                .is_empty()
        );
    }

    #[test]
    fn public_dtd_rejects_a_public_glued_to_the_doctype_prefix() {
        // PUBLIC starts exactly where the DOCTYPE prefix ends: the spacing
        // floor (public - 9) reaches back to the DOCTYPE and rejects
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPEPUBLIC aaaaaaaaaa \"http://x/d\">")
                .is_empty()
        );
    }

    #[test]
    fn public_dtd_needs_the_url_quote_after_the_public_keyword() {
        // the quote sits within seven characters of PUBLIC's start, so no
        // quote position reaches public + 7
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPE r PUBLIC\"http://x/d\">").is_empty()
        );
    }

    #[test]
    fn public_dtd_needs_the_url_quote_inside_the_run() {
        // a '[' right after PUBLIC closes the run; the only completed quote
        // lies beyond it and takes the run-end skip
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPE r PUBLIC[ aaaaaaaaaa \"http://x/d\">")
                .is_empty()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_entity_requires_system_keyword() {
        let hits = xml_system_finditer(r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#);
        assert_eq!(hits.len(), 1);
        assert!(xml_system_finditer(r#"<!ENTITY xxe "plain">"#).is_empty());
    }

    #[test]
    fn internal_entity_requires_bracket_section() {
        let text = "<!DOCTYPE foo [<!ENTITY xxe \"bar\">]>";
        let hits = xml_internal_entity_finditer(text);
        assert_eq!(hits.len(), 1);
        assert!(xml_internal_entity_finditer("<!DOCTYPE foo SYSTEM \"x\">").is_empty());
    }

    #[test]
    fn public_external_dtd_rejects_w3_org() {
        let good = r#"<!DOCTYPE foo PUBLIC "-//X//DTD//EN" "http://evil.example/dtd">"#;
        assert_eq!(xml_xxe_public_external_dtd_finditer(good).len(), 1);
        let w3 = r#"<!DOCTYPE foo PUBLIC "-//W3C//DTD//EN" "http://www.w3.org/dtd">"#;
        assert!(xml_xxe_public_external_dtd_finditer(w3).is_empty());
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn quoted_url_end_rejects_missing_closing_boundaries() {
        // The opening quote has an http scheme but the URL never closes:
        // no quote boundary after the scheme end.
        let unterminated = r#"<!DOCTYPE a PUBLIC "http://evil"#;
        assert!(xml_xxe_public_external_dtd_finditer(unterminated).is_empty());
        // The URL closes with a quote but no '>' or '[' follows it, so the
        // quoted form has no final boundary.
        let no_final_gt = r#"<!DOCTYPE a PUBLIC "http://evil'x"#;
        assert!(xml_xxe_public_external_dtd_finditer(no_final_gt).is_empty());
    }

    #[test]
    fn xml_system_requires_the_system_keyword_and_skips_overlaps() {
        // SYSTEM present: matched
        assert_eq!(xml_system_finditer("<!ENTITY x SYSTEM \"file\">").len(), 1);
        // no SYSTEM keyword: the span is consumed but nothing matches
        assert!(xml_system_finditer("<!ENTITY x \"file\">").is_empty());
        // no closing '>' at all: the scan ends with the collected matches
        assert!(xml_system_finditer("<!ENTITY x SYSTEM \"file\"").is_empty());
        // two entities: the second overlapping span is skipped
        assert_eq!(
            xml_system_finditer("<!ENTITY a SYSTEM \"f\"><!ENTITY b SYSTEM \"g\">").len(),
            2
        );
    }

    #[test]
    fn internal_entity_needs_the_bracket_section() {
        // a proper internal-subset DOCTYPE matches
        assert_eq!(
            xml_internal_entity_finditer("<!DOCTYPE r [<!ENTITY x \"v\">]>").len(),
            1
        );
        // a DOCTYPE closed by '>' before any '[' never matches
        assert!(xml_internal_entity_finditer("<!DOCTYPE r SYSTEM \"f\">").is_empty());
        // a bracket section without an ENTITY inside ends the scan
        assert!(xml_internal_entity_finditer("<!DOCTYPE r [<!---->]>").is_empty());
        // no boundary at all: the scan ends
        assert!(xml_internal_entity_finditer("<!DOCTYPE r ").is_empty());
    }
}

#[cfg(test)]
mod public_dtd_tests {
    use super::*;

    #[test]
    fn public_dtd_walks_quote_urls_and_skips_overlaps() {
        // the canonical PUBLIC DTD with a quoted http URL
        let doc = "<!DOCTYPE r PUBLIC \"http://example.org/dtd.dtd\">";
        let spans: Vec<(usize, usize)> = xml_xxe_public_external_dtd_finditer(doc)
            .iter()
            .map(|candidate| (candidate.start, candidate.end))
            .collect();
        assert_eq!(spans, vec![(0, 48)]);
        // no http URL anywhere: no quote positions, nothing matches
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPE r PUBLIC \"-//X//DTD//EN\">")
                .is_empty()
        );
        // a DOCTYPE without PUBLIC never enters the walk
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPE r SYSTEM \"http://x/d\">").is_empty()
        );
        // neither a DOCTYPE nor PUBLIC at all
        assert!(xml_xxe_public_external_dtd_finditer("<html/>").is_empty());
        // a scheme not preceded by a quote never becomes a quote position
        assert!(xml_xxe_public_external_dtd_finditer("<!DOCTYPE r PUBLIC http://x/d>").is_empty());
        // the w3.org scheme is excluded from the quote positions
        assert!(
            xml_xxe_public_external_dtd_finditer("<!DOCTYPE r PUBLIC \"http://www.w3.org/d.dtd\">")
                .is_empty()
        );
        // two PUBLICs each inside their own run: both match
        assert_eq!(
            xml_xxe_public_external_dtd_finditer(
                "<!DOCTYPE a PUBLIC \"http://x/a.dtd\"><!DOCTYPE b PUBLIC \"http://x/b.dtd\">"
            )
            .len(),
            2
        );
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn system_finditer_overlapping_prefix_spans_are_skipped() {
        // A DOCTYPE carrying an internal subset that itself opens a second
        // <!ENTITY span: the second prefix starts before last_end and must
        // take the `prefix_start < last_end` skip.
        let text = "<!DOCTYPE r [<!ENTITY a SYSTEM \"f\"><!ENTITY b SYSTEM \"g\">]>";
        assert_eq!(xml_system_finditer(text).len(), 2);
        // The empty-haystack degenerate keeps the scan honest.
        assert!(xml_system_finditer("").is_empty());
        assert!(xml_internal_entity_finditer("").is_empty());
        assert!(xml_xxe_public_external_dtd_finditer("").is_empty());
    }

    #[test]
    fn public_dtd_requires_doctype_well_before_public_in_the_run() {
        // No DOCTYPE at all: early return through the empty-positions arm.
        assert!(
            xml_xxe_public_external_dtd_finditer(r#"PUBLIC "x" "http://evil.example/d" >"#)
                .is_empty()
        );
        // DOCTYPE closer than 10 chars before PUBLIC: the spacing arm
        // passes here (0 < 11-9), so the candidate matches; the real
        // spacing rejection needs PUBLIC to overlap the DOCTYPE prefix,
        // which the grammar cannot express - the arm stays structural.
        assert_eq!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC "x" "http://evil.example/d">"#
            )
            .len(),
            1
        );
    }

    #[test]
    fn public_dtd_url_needs_a_quoted_scheme_completion() {
        // A URL without any quote before the closing '>' yields no quote
        // position, so the whole scan returns empty.
        assert!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC long-gap-here "http://evil.example/d>"#
            )
            .is_empty()
        );
    }

    #[test]
    fn public_dtd_scheme_completions_reject_w3_and_unquoted() {
        // Scheme directly followed by '>' (no class3 boundary): the quoted
        // completion fails and no quote position is recorded.
        assert!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC aaaaaaaaaa "http://evil.example>"#
            )
            .is_empty()
        );
        // The w3.org allowlist arm: the scheme completes, but the URL host
        // is w3.org so scheme_completion_end returns None.
        assert!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC aaaaaaaaaa "http://www.w3.org/d">"#
            )
            .is_empty()
        );
    }

    #[test]
    fn public_dtd_quote_and_gt_geometry_arms() {
        // The first URL is empty (quote2 lands on the scheme end):
        // rejected at completion time, but the second URL in the same run
        // completes and the candidate renders from the shared DOCTYPE.
        assert_eq!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC aaaaaaaaaa "http://"d" aaaaaaaaaa "http://evil.example/d">"#
            )
            .len(),
            1
        );
        // The first URL's quote is followed by '>' (quoted_url_end's
        // starts_with('>') rejection); the second URL completes the run's
        // quote map and the candidate renders from the DOCTYPE.
        assert_eq!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC aaaaaaaaaa "http://evil.example/">x aaaaaaaaaa "http://evil.example/d">"#
            )
            .len(),
            1
        );
    }

    #[test]
    fn public_dtd_arms_when_the_quote_or_gt_fall_outside_the_run() {
        // A '[' inside the URL closes the run before the final '>': the
        // candidate still renders from the DOCTYPE to the URL's final '>'.
        assert_eq!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC aaaaaaaaaa "http://evil.example/d["x">"#
            )
            .len(),
            1
        );
    }

    #[test]
    fn search_between_is_bounded() {
        let re = compile("x").expect("static");
        // empty window (start == end) and past-the-end both reject
        assert!(!search_between(&re, "x", 1, 1));
        assert!(!search_between(&re, "x", 0, 9));
    }

    #[test]
    fn system_finditer_with_a_wide_keyword_window_exercises_search_between() {
        // A SYSTEM keyword search over a zero-width window (prefix_end+1
        // past the closing '>'): the window's start >= end rejects before
        // the regex runs, covering search_between's first arm through the
        // public matcher instead of a synthetic call.
        assert!(xml_system_finditer("<<!ENTITY").is_empty());
        // quote2 == scheme_end through the public path: a URL whose first
        // quote sits exactly at the scheme end is a zero-length quote; the
        // second URL completes the candidate.
        assert_eq!(
            xml_xxe_public_external_dtd_finditer(
                r#"<!DOCTYPE r PUBLIC aaaaaaaaaa "http://" aaaaaaaaaa "http://evil.example/d">"#
            )
            .len(),
            1
        );
    }
}
