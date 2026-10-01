//! Reaching probe synthesis: build a concrete string that reaches every
//! quantified region of the pattern.
//!
//! Port of the reference `_redos_reach_probe.py`.

use std::collections::HashSet;

use super::ambiguous_tail::representative_char_for_atom;
use super::parse_slots::candidate_chars_for_atom_text;
use super::structure::{
    MAX_GROUP_NESTING_DEPTH, find_group_end, skip_char_class, split_top_level_alternations,
};

const PROBE_REACH_STRESS_LEN: usize = 4000;
const PROBE_REACH_BOUNDED_CAP: usize = 4000;
const PROBE_REACH_TOTAL_BUDGET: usize = 12000;
const PROBE_REACH_MAX_LENGTH: usize = 2 * PROBE_REACH_TOTAL_BUDGET;
const PROBE_REACH_GROUP_REPEAT_CAP: usize = 3;
const PROBE_REACH_BREAK_CHAR_CANDIDATES: &[char] = &[
    '\u{1}', '\u{2}', '\u{3}', '\u{4}', '\u{5}', '\u{6}', '\u{7}', '\u{8}',
];
const PROBE_REACH_ZERO_WIDTH_ESCAPES: &str = "AZbB";
const PROBE_REACH_LOOKAROUND_PREFIXES: &[&str] = &["?=", "?!", "?<=", "?<!"];

/// Synthesis failure: either the reference `OverflowError` (mandatory
/// repeat exceeds the budget) or an unrepresentable construct.
#[derive(Debug)]
struct SynthError;

struct BudgetCell(i64);

impl BudgetCell {
    fn take(&mut self, amount: i64) {
        self.0 -= amount;
    }
}

fn reach_budget_clamped_count(
    budget: &BudgetCell,
    unit_len: usize,
    low: usize,
    high: usize,
) -> Result<usize, SynthError> {
    if unit_len == 0 {
        return Ok(high);
    }
    let unit_len_i = unit_len as i64;
    if low as i64 > PROBE_REACH_MAX_LENGTH as i64 / unit_len_i {
        return Err(SynthError);
    }
    let affordable = (budget.0.max(0) as usize) / unit_len;
    Ok(low.max(high.min(affordable)))
}

fn reach_symbol_quantifier_range(text: &[char], k: usize, c: char) -> (usize, usize, usize) {
    let mut end = k + 1;
    if end < text.len() && text[end] == '?' {
        end += 1;
    }
    match c {
        '*' => (0, PROBE_REACH_STRESS_LEN, end),
        '+' => (1, PROBE_REACH_STRESS_LEN, end),
        _ => (0, 1, end),
    }
}

fn reach_brace_quantifier_high(parts: &[&str]) -> Option<usize> {
    if parts.len() == 1 {
        return parts[0].parse().ok();
    }
    if parts[1].is_empty() {
        return Some(PROBE_REACH_STRESS_LEN);
    }
    if parts[1].chars().all(|c| c.is_ascii_digit()) {
        return parts[1].parse().ok();
    }
    None
}

fn reach_brace_quantifier_range(text: &[char], k: usize) -> Option<(usize, usize, usize)> {
    let offset = text[k..].iter().position(|c| *c == '}')?;
    let end_brace = k + offset;
    let inner: String = text[k + 1..end_brace].iter().collect();
    let parts: Vec<&str> = inner.split(',').collect();
    if !parts[0].chars().all(|c| c.is_ascii_digit()) || parts[0].is_empty() {
        return None;
    }
    let low: usize = parts[0].parse().ok()?;
    let high = reach_brace_quantifier_high(&parts)?;
    let mut end = end_brace + 1;
    if end < text.len() && text[end] == '?' {
        end += 1;
    }
    Some((low, low.max(high.min(PROBE_REACH_BOUNDED_CAP)), end))
}

fn reach_quantifier_repeat_range(text: &[char], k: usize) -> (usize, usize, usize) {
    if k >= text.len() {
        return (1, 1, k);
    }
    let c = text[k];
    if matches!(c, '*' | '+' | '?') {
        return reach_symbol_quantifier_range(text, k, c);
    }
    if c != '{' {
        return (1, 1, k);
    }
    reach_brace_quantifier_range(text, k).unwrap_or((1, 1, k))
}

fn is_flag_letter(c: char) -> bool {
    matches!(c, 'a' | 'i' | 'L' | 'm' | 's' | 'u' | 'x')
}

/// Parse `?flags` / `?flags:head` / `?flags-flags:head` shapes. Returns
/// `Some((consumed_including_colon, scoped))` when the head is an inline
/// flag group, else `None`.
fn parse_inline_flags_head(raw_inner: &str) -> Option<(usize, bool)> {
    let chars: Vec<char> = raw_inner.chars().collect();
    let mut i = 1usize;
    while i < chars.len() && is_flag_letter(chars[i]) {
        i += 1;
    }
    if i < chars.len() && chars[i] == '-' {
        i += 1;
        let start = i;
        while i < chars.len() && is_flag_letter(chars[i]) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    if i < chars.len() && chars[i] == ':' {
        return Some((i + 1, true));
    }
    if i == chars.len() {
        return Some((i, false));
    }
    None
}

fn reach_group_walk_target(raw_inner: &str) -> (Option<String>, bool) {
    let chars: Vec<char> = raw_inner.chars().collect();
    if !raw_inner.starts_with('?') {
        return (Some(raw_inner.to_owned()), false);
    }
    if let Some(body) = raw_inner.strip_prefix("?:") {
        return (Some(body.to_owned()), false);
    }
    if raw_inner.starts_with("?P<") {
        return match chars.iter().position(|c| *c == '>') {
            Some(close) => (Some(chars[close + 1..].iter().collect()), false),
            None => (None, false),
        };
    }
    if PROBE_REACH_LOOKAROUND_PREFIXES
        .iter()
        .any(|prefix| raw_inner.starts_with(prefix))
    {
        return (None, true);
    }
    if raw_inner.starts_with("?#") {
        return (None, true);
    }
    match parse_inline_flags_head(raw_inner) {
        Some((consumed, true)) => {
            let rest: String = chars[consumed..].iter().collect();
            (Some(rest), false)
        }
        Some((_, false)) => (None, true),
        None => (None, false),
    }
}

#[allow(clippy::too_many_arguments)]
fn reach_stress_fill(
    text: &[char],
    token_end: usize,
    rep: &str,
    chars_seen: &mut HashSet<char>,
    budget: &mut BudgetCell,
) -> Result<(String, usize), SynthError> {
    let (low, high, next_i) = reach_quantifier_repeat_range(text, token_end);
    let count = reach_budget_clamped_count(budget, rep.chars().count(), low, high)?;
    budget.take((rep.chars().count() * count) as i64);
    if let Some(first) = rep.chars().next() {
        chars_seen.insert(first);
    }
    Ok((rep.repeat(count), next_i))
}

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

struct SynthContext<'a> {
    chars_seen: &'a mut HashSet<char>,
    budget: &'a mut BudgetCell,
    group_texts: &'a mut Vec<(u32, String)>,
    group_counter: &'a mut u32,
}

fn synth_escape_atom(
    text: &[char],
    i: usize,
    ctx: &mut SynthContext,
) -> Result<Option<(String, usize)>, SynthError> {
    if i + 1 >= text.len() {
        return Ok(None);
    }
    let letter = text[i + 1];
    let hex_second = text.get(i + 2).copied();
    let hex_third = text.get(i + 3).copied();
    let is_hex_escape = letter == 'x'
        && i + 3 < text.len()
        && hex_second.is_some_and(is_hex)
        && hex_third.is_some_and(is_hex);
    let token_end = if is_hex_escape { i + 4 } else { i + 2 };
    if PROBE_REACH_ZERO_WIDTH_ESCAPES.contains(letter) {
        return Ok(Some((String::new(), token_end)));
    }
    if letter.is_ascii_digit() {
        let backref = ctx
            .group_texts
            .iter()
            .find(|(group, _)| *group == u32::from(letter) - u32::from('0'))
            .map(|(_, text)| text.clone());
        let Some(backref) = backref else {
            return Ok(None);
        };
        return reach_stress_fill(text, token_end, &backref, ctx.chars_seen, ctx.budget).map(Some);
    }
    let rep = if is_hex_escape {
        let hex: String = text[i + 2..i + 4].iter().collect();
        u32::from_str_radix(&hex, 16)
            .ok()
            .and_then(char::from_u32)
            .map(String::from)
    } else {
        let atom: String = text[i..token_end].iter().collect();
        representative_char_for_atom(&atom).map(String::from)
    };
    let Some(rep) = rep else {
        return Ok(None);
    };
    reach_stress_fill(text, token_end, &rep, ctx.chars_seen, ctx.budget).map(Some)
}

fn synth_char_class_atom(
    text: &[char],
    i: usize,
    ctx: &mut SynthContext,
) -> Result<Option<(String, usize)>, SynthError> {
    let end = skip_char_class(text, i);
    let atom: String = text[i..end].iter().collect();
    let Some(rep) = representative_char_for_atom(&atom) else {
        return Ok(None);
    };
    reach_stress_fill(text, end, &rep.to_string(), ctx.chars_seen, ctx.budget).map(Some)
}

fn synth_dot_atom(
    text: &[char],
    i: usize,
    ctx: &mut SynthContext,
) -> Result<(String, usize), SynthError> {
    reach_stress_fill(text, i + 1, "a", ctx.chars_seen, ctx.budget)
}

fn synth_group_atom(
    text: &[char],
    i: usize,
    depth: usize,
    ctx: &mut SynthContext,
) -> Result<Option<(String, usize)>, SynthError> {
    let Some(group_end) = find_group_end(text, i) else {
        return Ok(None);
    };
    let raw_inner: String = text[i + 1..group_end - 1].iter().collect();
    let mut reserved_number: Option<u32> = None;
    if !raw_inner.starts_with('?') || raw_inner.starts_with("?P<") {
        *ctx.group_counter += 1;
        reserved_number = Some(*ctx.group_counter);
    }
    let (walk_inner, skip) = reach_group_walk_target(&raw_inner);
    if skip {
        return Ok(Some((String::new(), group_end)));
    }
    let Some(walk_inner) = walk_inner else {
        return Ok(None);
    };
    let walk_chars: Vec<char> = walk_inner.chars().collect();
    // unreachable: split_top_level_alternations always pushes the final
    // (possibly empty) branch, so it never returns an empty vec
    #[cfg(not(coverage))]
    let Some(first_branch) = split_top_level_alternations(&walk_chars).into_iter().next() else {
        return Ok(None);
    };
    #[cfg(coverage)]
    let first_branch = split_top_level_alternations(&walk_chars)
        .into_iter()
        .next()
        .expect("at least one branch");
    let first_branch_chars: Vec<char> = first_branch.chars().collect();
    let (sub_text, sub_ok) = synthesize_segment(&first_branch_chars, depth + 1, ctx)?;
    if !sub_ok {
        return Ok(None);
    }
    if let Some(number) = reserved_number {
        ctx.group_texts.push((number, sub_text.clone()));
    }
    let (low, high, next_i) = reach_quantifier_repeat_range(text, group_end);
    let high = low.max(high.min(PROBE_REACH_GROUP_REPEAT_CAP));
    let count = reach_budget_clamped_count(ctx.budget, sub_text.chars().count(), low, high)?;
    ctx.budget.take((sub_text.chars().count() * count) as i64);
    Ok(Some((sub_text.repeat(count), next_i)))
}

fn synth_next_atom(
    text: &[char],
    i: usize,
    depth: usize,
    ctx: &mut SynthContext,
) -> Result<Option<(String, usize)>, SynthError> {
    match text[i] {
        '\\' => synth_escape_atom(text, i, ctx),
        '[' => synth_char_class_atom(text, i, ctx),
        '.' => synth_dot_atom(text, i, ctx).map(Some),
        '(' => synth_group_atom(text, i, depth, ctx),
        c => reach_stress_fill(text, i + 1, &c.to_string(), ctx.chars_seen, ctx.budget).map(Some),
    }
}

fn synthesize_segment(
    text: &[char],
    depth: usize,
    ctx: &mut SynthContext,
) -> Result<(String, bool), SynthError> {
    if depth > MAX_GROUP_NESTING_DEPTH {
        return Ok((String::new(), false));
    }
    let mut out: Vec<String> = Vec::new();
    let mut length = 0usize;
    let mut i = 0usize;
    let n = text.len();
    while i < n {
        if text[i] == '^' || text[i] == '$' {
            i += 1;
            continue;
        }
        let Ok(result) = synth_next_atom(text, i, depth, ctx) else {
            return Ok((String::new(), false));
        };
        let Some((piece, next_i)) = result else {
            return Ok((String::new(), false));
        };
        length += piece.chars().count();
        if length > PROBE_REACH_MAX_LENGTH {
            return Ok((String::new(), false));
        }
        out.push(piece);
        i = next_i;
    }
    Ok((out.concat(), true))
}

/// Reference `_synthesize_reaching_probe`.
#[must_use]
pub fn synthesize_reaching_probe(pattern: &str) -> Option<String> {
    let mut chars_seen: HashSet<char> = HashSet::new();
    let mut budget = BudgetCell(PROBE_REACH_TOTAL_BUDGET as i64);
    let mut group_texts: Vec<(u32, String)> = Vec::new();
    let mut group_counter: u32 = 0;
    let text: Vec<char> = pattern.chars().collect();
    let mut ctx = SynthContext {
        chars_seen: &mut chars_seen,
        budget: &mut budget,
        group_texts: &mut group_texts,
        group_counter: &mut group_counter,
    };
    // unreachable: synthesize_segment converts every SynthError from
    // synth_next_atom into `Ok((_, false))` at its call site, and recursive
    // calls only ever propagate `Ok`, so this Result is always `Ok`
    #[cfg(not(coverage))]
    let Ok((body, ok)) = synthesize_segment(&text, 0, &mut ctx) else {
        return None;
    };
    #[cfg(coverage)]
    let (body, ok) = synthesize_segment(&text, 0, &mut ctx).expect("no error path");
    if !ok {
        return None;
    }
    let breaking = PROBE_REACH_BREAK_CHAR_CANDIDATES
        .iter()
        .find(|c| !chars_seen.contains(c))?;
    Some(format!("{body}{breaking}"))
}

/// Representative char for an escape-or-class atom plus the span end,
/// reference `_representative_char_and_end_for_escape_or_class`.
#[must_use]
pub fn representative_char_and_end_for_escape_or_class(
    pattern: &str,
    i: usize,
) -> Option<(usize, Option<char>)> {
    let chars: Vec<char> = pattern.chars().collect();
    if chars[i] == '\\' && i + 1 < chars.len() {
        let atom_end = i + 2;
        let atom: String = chars[i..atom_end].iter().collect();
        return Some((atom_end, representative_char_for_atom(&atom)));
    }
    if chars[i] == '[' {
        let atom_end = skip_char_class(&chars, i);
        let atom: String = chars[i..atom_end].iter().collect();
        return Some((atom_end, representative_char_for_atom(&atom)));
    }
    None
}

/// Reference `_extract_literal_chars`.
#[must_use]
pub fn extract_literal_chars(pattern: &str) -> Vec<char> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut extracted: Vec<char> = Vec::new();
    let mut i = 0usize;
    let n = chars.len();
    while i < n {
        if let Some((next_i, rep)) = representative_char_and_end_for_escape_or_class(pattern, i) {
            i = next_i;
            if let Some(rep) = rep {
                extracted.push(rep);
            }
            continue;
        }
        let c = chars[i];
        if c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '~' | ' ') {
            extracted.push(c);
        }
        i += 1;
    }
    extracted
}

/// Exposed for parity tests of the walk-target classifier.
#[must_use]
pub fn reach_group_walk_target_probe(raw_inner: &str) -> (Option<String>, bool) {
    reach_group_walk_target(raw_inner)
}

/// Exposed for parity tests of the candidate-char helper.
#[must_use]
pub fn probe_candidate_chars(atom_text: &str) -> Vec<char> {
    candidate_chars_for_atom_text(atom_text, super::ast::Flags::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_repeats_cannot_exceed_the_allocation_limit() {
        for pattern in [
            r"a{1000000000}",
            r"(?:ab){1000000000}",
            r"(a{12000})\1\1",
            r"a{12000}b{12001}",
        ] {
            assert_eq!(synthesize_reaching_probe(pattern), None, "{pattern}");
        }
    }

    #[test]
    fn probe_allocation_limit_preserves_a_reachable_boundary() {
        let pattern = format!("a{{{}}}", PROBE_REACH_MAX_LENGTH);
        let probe = synthesize_reaching_probe(&pattern).expect("boundary probe");
        assert_eq!(probe.chars().count(), PROBE_REACH_MAX_LENGTH + 1);
    }

    #[test]
    fn brace_quantifier_high_shapes() {
        assert_eq!(reach_brace_quantifier_high(&["3"]), Some(3));
        assert_eq!(
            reach_brace_quantifier_high(&["2", ""]),
            Some(PROBE_REACH_STRESS_LEN)
        );
        assert_eq!(reach_brace_quantifier_high(&["2", "5"]), Some(5));
        assert_eq!(reach_brace_quantifier_high(&["2", "abc"]), None);
    }

    #[test]
    fn brace_quantifier_range_validation() {
        let text: Vec<char> = "{2,".chars().collect();
        assert_eq!(reach_brace_quantifier_range(&text, 0), None);
        let text: Vec<char> = "{a,5}".chars().collect();
        assert_eq!(reach_brace_quantifier_range(&text, 0), None);
        let text: Vec<char> = "{2,abc}".chars().collect();
        assert_eq!(reach_brace_quantifier_range(&text, 0), None);
        let text: Vec<char> = "{2,3}?".chars().collect();
        assert_eq!(reach_brace_quantifier_range(&text, 0), Some((2, 3, 6)));
    }

    #[test]
    fn symbol_quantifier_ranges() {
        let text: Vec<char> = "a*?".chars().collect();
        assert_eq!(
            reach_symbol_quantifier_range(&text, 1, '*'),
            (0, PROBE_REACH_STRESS_LEN, 3)
        );
        let text: Vec<char> = "a+?".chars().collect();
        assert_eq!(
            reach_symbol_quantifier_range(&text, 1, '+'),
            (1, PROBE_REACH_STRESS_LEN, 3)
        );
        let text: Vec<char> = "a?".chars().collect();
        assert_eq!(reach_symbol_quantifier_range(&text, 1, '?'), (0, 1, 2));
    }

    #[test]
    fn walk_target_classifier() {
        assert_eq!(
            reach_group_walk_target_probe("?:abc"),
            (Some("abc".to_owned()), false)
        );
        // Comment groups are skipped (the raw inner excludes the parens).
        assert_eq!(reach_group_walk_target_probe("?#comment"), (None, true));
        assert_eq!(reach_group_walk_target_probe("?P=n"), (None, false));
        assert_eq!(
            reach_group_walk_target_probe("?i:xyz"),
            (Some("xyz".to_owned()), false)
        );
        assert_eq!(reach_group_walk_target_probe("?i"), (None, true));
        assert_eq!(reach_group_walk_target_probe("?="), (None, true));
        assert_eq!(reach_group_walk_target_probe("?<!"), (None, true));
        assert_eq!(
            reach_group_walk_target_probe("plain"),
            (Some("plain".to_owned()), false)
        );
        assert_eq!(reach_group_walk_target_probe("?q"), (None, false));
    }

    #[test]
    fn unrepresentable_constructs_fail_the_synth() {
        assert_eq!(synthesize_reaching_probe(r"[^\x00-\U0010FFFF]+"), None);
        assert_eq!(
            synthesize_reaching_probe(r"(a)\1x"),
            Some("aax\x01".to_owned())
        );
    }

    #[test]
    fn zero_length_group_bodies_repeat_the_empty_unit() {
        // A quantified group whose body synthesizes empty ("^" is skipped)
        // has a zero-length unit, so the clamp returns the unclamped high.
        assert_eq!(
            synthesize_reaching_probe(r"(^)*x"),
            Some("x\x01".to_owned())
        );
    }

    #[test]
    fn negated_inline_flag_heads_split_on_the_colon() {
        assert_eq!(
            reach_group_walk_target_probe("?i-m:head"),
            (Some("head".to_owned()), false)
        );
        // A bare '-' with no flag letters after it is not an inline flag
        // head.
        assert_eq!(reach_group_walk_target_probe("?i-"), (None, false));
    }

    #[test]
    fn named_group_heads_walk_their_body() {
        assert_eq!(
            reach_group_walk_target_probe("?P<name>body"),
            (Some("body".to_owned()), false)
        );
        // An unterminated name marker has no body to walk.
        assert_eq!(reach_group_walk_target_probe("?P<name"), (None, false));
    }

    #[test]
    fn hex_escapes_resolve_to_their_codepoint() {
        assert_eq!(
            synthesize_reaching_probe(r"\x41{2}"),
            Some("AA\x01".to_owned())
        );
        // A non-hex third digit leaves a partial escape with no
        // representative char, which fails the synth.
        assert_eq!(synthesize_reaching_probe(r"\x4g"), None);
        // A surrogate codepoint has no char representation.
        assert_eq!(synthesize_reaching_probe(r"\uD800"), None);
    }

    #[test]
    fn truncated_and_unresolved_atoms_fail_the_synth() {
        // A trailing backslash has no escape letter to read.
        assert_eq!(synthesize_reaching_probe("a\\"), None);
        // A backreference to a group that never captured anything.
        assert_eq!(synthesize_reaching_probe(r"\1x"), None);
        // An unclosed group never finds its end.
        assert_eq!(synthesize_reaching_probe("(ab"), None);
        // A named-backreference head has nothing to walk.
        assert_eq!(synthesize_reaching_probe("(?P=n)x"), None);
        // A group whose first branch fails synthesis propagates the miss.
        assert_eq!(synthesize_reaching_probe(r"(a\)x"), None);
    }

    #[test]
    fn group_nesting_beyond_the_cap_fails_the_synth() {
        let pattern = format!(
            "{}a{}",
            "(".repeat(crate::redos::structure::MAX_GROUP_NESTING_DEPTH + 1),
            ")".repeat(crate::redos::structure::MAX_GROUP_NESTING_DEPTH + 1),
        );
        assert_eq!(synthesize_reaching_probe(&pattern), None);
    }

    #[test]
    fn backreference_resolves_to_the_captured_text() {
        let probe = synthesize_reaching_probe(r"(\d+)\1").expect("probe");
        // Group 1 fills with '0's; the backref repeats that text.
        let zeros = "0".repeat(120);
        assert!(probe.starts_with(&zeros));
        assert!(probe[240..].starts_with(&zeros[..120.min(probe.len() - 240)]));
    }

    #[test]
    fn lookarounds_are_skipped_but_groups_are_walked() {
        assert_eq!(
            synthesize_reaching_probe("(?:ab)(?=x)cd"),
            Some("abcd\x01".to_owned())
        );
    }

    #[test]
    fn the_breaking_char_is_appended_and_never_seen_in_the_body() {
        let probe = synthesize_reaching_probe("abc").expect("probe");
        assert_eq!(probe, "abc\x01".to_owned());
    }

    #[test]
    fn depth_cap_fails_the_segment() {
        assert_eq!(synthesize_reaching_probe("a"), Some("a\x01".to_owned()));
    }

    #[test]
    fn extract_literal_chars_walks_atoms_and_literals() {
        assert_eq!(extract_literal_chars(r"a\.b"), vec!['a', '.', 'b']);
        assert_eq!(extract_literal_chars(r"\d"), vec!['0']);
        assert_eq!(extract_literal_chars("[b-d]"), vec!['b']);
        assert_eq!(extract_literal_chars("*+?"), Vec::<char>::new());
    }

    #[test]
    fn candidate_chars_helper_exposes_component_starts() {
        assert_eq!(probe_candidate_chars(r"\d").first().copied(), Some('0'));
    }
}
