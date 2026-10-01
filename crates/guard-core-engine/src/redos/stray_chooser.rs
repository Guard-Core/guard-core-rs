//! Stray character selection with child-verified forcing points.
//!
//! Port of the reference `_redos_stray_chooser.py`: candidates are only
//! ever verified against the untrusted pattern inside a killable child,
//! never inline.

use std::time::Instant;

use super::child::{ChildRequest, ChildSpawnError, run_child_request};
use super::intervals::IntervalSet;
use super::parse_slots::{PairingAtom, Slot, pattern_slots};
use super::structure::find_group_end;
use super::timeout::BuilderTimeout;

const REACH_PROBE_STRAY_BYTE: char = '\0';
const LEADING_PREFIX_METACHARS: &str = ".^$*+?{}[]()|\\";
const STRAY_FALLBACK_CANDIDATES: &[&str] = &[
    "\u{0}", "z", "\n", " ", "-", "\t", "\r", "9", "!", "~", "_", ".", "A", "\u{1f}", "\u{7f}", "/",
];
const STRAY_CANDIDATE_CAP: usize = 16;
const STRAY_VERIFY_FILL_COUNTS: &[usize] = &[1, 2, 8];
const STRAY_VERIFY_TIMEOUT_SECONDS: f64 = 0.5;

/// The reference `_StrayContext`.
#[derive(Debug, Clone)]
pub struct StrayContext {
    pub pattern: String,
    pub flags: super::ast::Flags,
    pub prefix: String,
    pub pattern_union: IntervalSet,
    pub deadline: Option<Instant>,
}

fn unwrap_leading_transparent_group(pattern: &str) -> String {
    let mut text = pattern.to_owned();
    loop {
        if !text.starts_with("(?:") {
            break;
        }
        let chars: Vec<char> = text.chars().collect();
        let Some(end) = find_group_end(&chars, 0) else {
            break;
        };
        if end != chars.len() {
            break;
        }
        text = chars[3..end - 1].iter().collect();
    }
    text
}

/// Reference `_leading_literal_prefix`.
#[must_use]
pub fn leading_literal_prefix(pattern: &str) -> String {
    let text = unwrap_leading_transparent_group(pattern);
    let chars: Vec<char> = text.chars().collect();
    let mut prefix: Vec<char> = Vec::new();
    let mut i = 0usize;
    let n = chars.len();
    while i < n {
        let c = chars[i];
        if c == '\\' && i + 1 < n && !chars[i + 1].is_alphanumeric() {
            prefix.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if LEADING_PREFIX_METACHARS.contains(c) {
            break;
        }
        prefix.push(c);
        i += 1;
    }
    prefix.into_iter().collect()
}

/// Reference `_fill_to_length`.
#[must_use]
pub fn fill_to_length(prefix: &str, fill_char: &str, stray: &str, length: usize) -> String {
    if length <= prefix.len() {
        return prefix.chars().take(length).collect();
    }
    let body_length = length - prefix.len();
    if body_length > 1 {
        return format!("{prefix}{}{stray}", fill_char.repeat(body_length - 1));
    }
    format!("{prefix}{}", fill_char.repeat(body_length))
}

fn homogeneous_unit(unit: &str) -> bool {
    unit.chars()
        .next()
        .is_none_or(|first| unit.chars().all(|c| c == first))
}

/// Reference `_repeat_probe_to_length`.
#[must_use]
pub fn repeat_probe_to_length(unit: &str, length: usize, stray: &str) -> String {
    if unit.is_empty() {
        return unit.to_owned();
    }
    let unit_len = unit.chars().count();
    let mut result: Vec<char> = unit.chars().cycle().take(length).collect();
    if homogeneous_unit(unit) || length.is_multiple_of(unit_len) {
        // The reference appends the stray as the last character.
        let stray_char = stray.chars().next().unwrap_or(REACH_PROBE_STRAY_BYTE);
        if let Some(last) = result.last_mut() {
            *last = stray_char;
        }
    }
    result.into_iter().collect()
}

/// Reference `_stray_for_pair`.
#[must_use]
pub fn stray_for_pair(left: &IntervalSet, right: &IntervalSet) -> String {
    let member = left.union(right).complement().first_member();
    char::from_u32(member.unwrap_or(0))
        .map_or_else(|| REACH_PROBE_STRAY_BYTE.to_string(), |c| c.to_string())
}

/// Reference `_first_complement_char`.
#[must_use]
pub fn first_complement_char(intervals: &IntervalSet) -> Option<String> {
    intervals
        .complement()
        .first_member()
        .and_then(char::from_u32)
        .map(String::from)
}

fn dedup_capped_candidates<I: IntoIterator<Item = Option<String>>>(candidates: I) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut result: Vec<String> = Vec::new();
    for candidate in candidates {
        let Some(candidate) = candidate else {
            continue;
        };
        if seen.contains(&candidate) {
            continue;
        }
        seen.push(candidate.clone());
        result.push(candidate);
        if result.len() >= STRAY_CANDIDATE_CAP {
            break;
        }
    }
    result
}

fn collect_pairing_intervals(slots: &[Slot]) -> Vec<IntervalSet> {
    let mut collected: Vec<IntervalSet> = Vec::new();
    for slot in slots {
        match slot {
            Slot::Pairing(PairingAtom { intervals, .. }) => {
                collected.push(intervals.clone());
            }
            Slot::NonPairing(non) => {
                if let Some(inner) = &non.inner {
                    for alternative in inner {
                        collected.extend(collect_pairing_intervals(alternative));
                    }
                }
            }
        }
    }
    collected
}

fn pattern_class_union(pattern: &str, flags: super::ast::Flags) -> IntervalSet {
    let Some(slots) = pattern_slots(pattern, flags) else {
        return IntervalSet::empty();
    };
    let mut union = IntervalSet::empty();
    for intervals in collect_pairing_intervals(&slots) {
        union = union.union(&intervals);
    }
    union
}

/// Reference `_pattern_complement_chars`.
#[must_use]
pub fn pattern_complement_chars(pattern: &str, flags: super::ast::Flags) -> Vec<String> {
    let Some(slots) = pattern_slots(pattern, flags) else {
        return Vec::new();
    };
    let mut chars: Vec<String> = Vec::new();
    for intervals in collect_pairing_intervals(&slots) {
        let Some(candidate) = first_complement_char(&intervals) else {
            continue;
        };
        if !chars.contains(&candidate) {
            chars.push(candidate);
        }
    }
    chars
}

/// Reference `_build_stray_context`.
#[must_use]
pub fn build_stray_context(
    pattern: &str,
    flags: super::ast::Flags,
    deadline: Option<Instant>,
) -> StrayContext {
    StrayContext {
        pattern: pattern.to_owned(),
        flags,
        prefix: leading_literal_prefix(pattern),
        pattern_union: pattern_class_union(pattern, flags),
        deadline,
    }
}

fn stray_verification_timeout(ctx: &StrayContext) -> Result<f64, BuilderTimeout> {
    let Some(deadline) = ctx.deadline else {
        return Ok(STRAY_VERIFY_TIMEOUT_SECONDS);
    };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .map(|d| d.as_secs_f64());
    let Some(remaining) = remaining else {
        return Err(BuilderTimeout(
            "Pattern validation probe construction exceeded its deadline".into(),
        ));
    };
    Ok(STRAY_VERIFY_TIMEOUT_SECONDS.min(remaining))
}

fn map_spawn_error(
    error: ChildSpawnError,
    timeout_text: &str,
    failed_text: &str,
) -> BuilderTimeout {
    match error {
        ChildSpawnError::Timeout => BuilderTimeout(timeout_text.to_owned()),
        other => BuilderTimeout(format!("{failed_text} ({other})")),
    }
}

/// Reference `_first_bounded_forcing_candidate`.
pub fn first_bounded_forcing_candidate(
    ctx: &StrayContext,
    candidates: &[String],
    probes: &[Vec<String>],
) -> Result<Option<String>, BuilderTimeout> {
    first_bounded_forcing_candidate_with(ctx, candidates, probes, &run_child_request)
}

/// The pure half of [`first_bounded_forcing_candidate`]: the child runner
/// is injected so tests can force every outcome deterministically.
pub(crate) fn first_bounded_forcing_candidate_with(
    ctx: &StrayContext,
    candidates: &[String],
    probes: &[Vec<String>],
    run: super::cost_arbiter::ChildRunner<'_>,
) -> Result<Option<String>, BuilderTimeout> {
    let timeout = stray_verification_timeout(ctx)?;
    let cases: Vec<(String, Vec<String>)> = candidates
        .iter()
        .cloned()
        .zip(probes.iter().cloned())
        .collect();
    let outcome = run(
        &ChildRequest::StrayVerify {
            pattern: ctx.pattern.clone(),
            flags: ctx.flags,
            cases,
        },
        timeout,
    );
    match outcome {
        Err(error) => Err(map_spawn_error(
            error,
            "Pattern validation stray verification exceeded its \
             killable-subprocess timeout",
            "Pattern validation stray verification killable-subprocess failed to run",
        )),
        Ok(super::child::ChildOutcome::Stray(None)) => Ok(None),
        Ok(super::child::ChildOutcome::Stray(Some(candidate))) => {
            if candidates.contains(&candidate) {
                Ok(Some(candidate))
            } else {
                Err(BuilderTimeout(
                    "Pattern validation stray verification \
                     killable-subprocess returned malformed output"
                        .into(),
                ))
            }
        }
        Ok(_) => Err(BuilderTimeout(
            "Pattern validation stray verification \
             killable-subprocess returned malformed output"
                .into(),
        )),
    }
}

fn class_intersection_stray_candidates(
    tail: &[IntervalSet],
    left: &IntervalSet,
    right: &IntervalSet,
    pattern_union: &IntervalSet,
) -> Vec<String> {
    let mut ordered: Vec<Option<String>> = tail.iter().map(first_complement_char).collect();
    ordered.push(first_complement_char(right));
    ordered.push(first_complement_char(&left.union(right)));
    ordered.push(first_complement_char(pattern_union));
    ordered.extend(
        STRAY_FALLBACK_CANDIDATES
            .iter()
            .map(|c| Some((*c).to_owned())),
    );
    dedup_capped_candidates(ordered)
}

fn stray_verify_probes(
    ctx: &StrayContext,
    fill_char: &str,
    candidates: &[String],
) -> Vec<Vec<String>> {
    candidates
        .iter()
        .map(|candidate| {
            STRAY_VERIFY_FILL_COUNTS
                .iter()
                .map(|count| {
                    fill_to_length(
                        &ctx.prefix,
                        fill_char,
                        candidate,
                        ctx.prefix.chars().count() + count + 1,
                    )
                })
                .collect()
        })
        .collect()
}

fn class_intersection_probe_forces_failure(
    ctx: &StrayContext,
    fill_char: &str,
    candidate: &str,
) -> Result<bool, BuilderTimeout> {
    let candidates = [candidate.to_owned()];
    let probes = stray_verify_probes(ctx, fill_char, &candidates);
    Ok(first_bounded_forcing_candidate(ctx, &candidates, &probes)?
        .is_some_and(|found| found == candidate))
}

/// Reference `choose_class_intersection_stray`.
pub fn choose_class_intersection_stray(
    ctx: &StrayContext,
    fill_char: &str,
    left: &IntervalSet,
    right: &IntervalSet,
    tail: &[IntervalSet],
) -> Result<String, BuilderTimeout> {
    let candidates = class_intersection_stray_candidates(tail, left, right, &ctx.pattern_union);
    let probes = stray_verify_probes(ctx, fill_char, &candidates);
    let chosen = first_bounded_forcing_candidate(ctx, &candidates, &probes)?;
    Ok(chosen.unwrap_or_else(|| stray_for_pair(left, right)))
}

fn repeat_unit_stray_candidates(pattern_union: &IntervalSet) -> Vec<String> {
    let mut ordered: Vec<Option<String>> = vec![first_complement_char(pattern_union)];
    ordered.extend(
        STRAY_FALLBACK_CANDIDATES
            .iter()
            .map(|c| Some((*c).to_owned())),
    );
    dedup_capped_candidates(ordered)
}

fn repeat_unit_verify_probes(unit: &str, candidates: &[String]) -> Vec<Vec<String>> {
    candidates
        .iter()
        .map(|candidate| {
            STRAY_VERIFY_FILL_COUNTS
                .iter()
                .map(|count| {
                    let unit_len = unit.chars().count();
                    repeat_probe_to_length(unit, unit_len * count, candidate)
                })
                .collect()
        })
        .collect()
}

/// Reference `choose_repeat_unit_stray`.
pub fn choose_repeat_unit_stray(ctx: &StrayContext, unit: &str) -> Result<String, BuilderTimeout> {
    if unit.is_empty() {
        return Ok(REACH_PROBE_STRAY_BYTE.to_string());
    }
    let candidates = repeat_unit_stray_candidates(&ctx.pattern_union);
    let probes = repeat_unit_verify_probes(unit, &candidates);
    let chosen = first_bounded_forcing_candidate(ctx, &candidates, &probes)?;
    Ok(chosen.unwrap_or_else(|| REACH_PROBE_STRAY_BYTE.to_string()))
}

/// Verifies a class-intersection stray candidate forces failure, exposing
/// the same decision the reference's helper makes (test seam).
pub fn verify_stray_forces_failure(
    ctx: &StrayContext,
    fill_char: &str,
    candidate: &str,
) -> Result<bool, BuilderTimeout> {
    class_intersection_probe_forces_failure(ctx, fill_char, candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::Flags;
    use crate::redos::child::ChildOutcome;
    use crate::redos::parse_slots::NonPairingSlot;

    /// Destructure a pairing slot; panics on any other variant.
    fn expect_pairing(slot: &Slot) -> &PairingAtom {
        match slot {
            Slot::Pairing(atom) => atom,
            other => panic!("expected pairing, got {other:?}"),
        }
    }

    /// Destructure a non-pairing slot; panics on any other variant.
    fn expect_non_pairing(slot: &Slot) -> &NonPairingSlot {
        match slot {
            Slot::NonPairing(non) => non,
            other => panic!("expected non-pairing, got {other:?}"),
        }
    }

    #[test]
    fn leading_literal_prefix_unwraps_transparent_groups() {
        assert_eq!(leading_literal_prefix(r"(?:<[^<>]*)"), "<");
    }

    #[test]
    fn leading_literal_prefix_handles_escaped_literal_runs() {
        assert_eq!(leading_literal_prefix(r"\.\.;[^/\\]*"), "..;");
    }

    #[test]
    fn leading_literal_prefix_empty_when_the_pattern_opens_with_a_metachar() {
        assert_eq!(leading_literal_prefix(r"[^<>]*x"), "");
    }

    #[test]
    fn fill_to_length_pads_truncates_and_places_the_stray() {
        assert_eq!(fill_to_length("ab", "x", "!", 4), "abx!");
        assert_eq!(fill_to_length("abcdef", "x", "!", 3), "abc");
        assert_eq!(fill_to_length("ab", "x", "!", 6), "abxxx!");
        // Body room of one or fewer never forces the stray in.
        assert_eq!(fill_to_length("ab", "x", "!", 3), "abx");
        assert_eq!(fill_to_length("ab", "x", "!", 2), "ab");
    }

    #[test]
    fn repeat_probe_forces_non_alignment_on_exact_multiples() {
        let result = repeat_probe_to_length("ab", 10, "\0");
        assert_eq!(result.chars().count(), 10);
        assert_eq!(result.chars().last(), Some('\0'));
    }

    #[test]
    fn repeat_probe_stays_pure_repetition_when_not_aligned() {
        let result = repeat_probe_to_length("abc", 10, "\0");
        assert_eq!(result.chars().count(), 10);
        assert!(!result.contains('\0'));
    }

    #[test]
    fn repeat_probe_empty_unit_returns_empty() {
        assert_eq!(repeat_probe_to_length("", 10, "\0"), "");
    }

    #[test]
    fn stray_for_pair_reaches_past_the_byte_range() {
        let left = IntervalSet::from_range(0, 0xFF);
        let right = IntervalSet::from_range(0, 0xFE);
        let stray = stray_for_pair(&left, &right);
        let code = stray.chars().next().map(u32::from).expect("char");
        assert!(code >= 0x100);
        assert!(!left.contains(code));
        assert!(!right.contains(code));
    }

    #[test]
    fn stray_for_pair_falls_back_to_nul_on_a_universal_union() {
        assert_eq!(
            stray_for_pair(&IntervalSet::full(), &IntervalSet::full()),
            "\0"
        );
    }

    #[test]
    fn first_complement_char_is_none_for_a_universal_set() {
        assert_eq!(first_complement_char(&IntervalSet::full()), None);
        // The complement starts at NUL, not at 'a' + 1.
        assert_eq!(
            first_complement_char(&IntervalSet::single(u32::from('a'))),
            Some("\0".to_owned())
        );
    }

    #[test]
    fn pattern_complement_chars_collect_per_intervals() {
        let chars = pattern_complement_chars(r"\d\d", Flags::default());
        assert_eq!(chars, vec!["\0".to_owned()]);
        // Parse failures contribute nothing.
        assert!(pattern_complement_chars("[oops", Flags::default()).is_empty());
    }

    #[test]
    fn build_stray_context_carries_the_pattern_union() {
        let ctx = build_stray_context(r"\d", Flags::default(), None);
        assert_eq!(ctx.pattern, r"\d");
        assert!(ctx.pattern_union.contains(u32::from('5')));
        assert!(!ctx.pattern_union.contains(u32::from('x')));
        assert_eq!(ctx.prefix, "");
    }

    #[test]
    fn choose_repeat_unit_stray_rejects_empty_units() {
        let ctx = build_stray_context("abc", Flags::default(), None);
        assert_eq!(choose_repeat_unit_stray(&ctx, "").expect("stray"), "\0");
    }

    #[test]
    fn choose_repeat_unit_stray_verifies_in_the_child() {
        let ctx = build_stray_context("abc", Flags::default(), None);
        // The literal pattern never matches a probe with stray breaks.
        let stray = choose_repeat_unit_stray(&ctx, "abc").expect("stray");
        assert!(!stray.is_empty());
    }

    #[test]
    fn choose_class_intersection_stray_prefers_tail_complements() {
        // The lookahead inserts a non-pairing slot, so the pairing filter's
        // catch-all arm runs; the tail class moves to slot 3.
        let pattern = r"\s*[\s\S]+(?=x)[\x00-\x08]";
        let flags = Flags::ignorecase_multiline();
        let slots =
            crate::redos::parse_slots::pattern_slots(pattern, flags).expect("pattern parses");
        let lookahead = expect_non_pairing(&slots[2]);
        assert!(lookahead.inner.is_some());
        let left = expect_pairing(&slots[0]);
        let middle = expect_pairing(&slots[1]);
        let _tail_atom = expect_pairing(&slots[3]);
        let fill_member = left
            .intervals
            .intersection(&middle.intervals)
            .first_member()
            .expect("overlap");
        let fill = char::from_u32(fill_member).expect("char");
        let ctx = build_stray_context(pattern, flags, None);
        let slots_ints: Vec<IntervalSet> = slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Pairing(atom) => Some(atom.intervals.clone()),
                Slot::NonPairing(_) => None,
            })
            .collect();
        assert_eq!(slots_ints.len(), 3);
        let stray = choose_class_intersection_stray(
            &ctx,
            &fill.to_string(),
            &left.intervals,
            &middle.intervals,
            &[slots_ints[2].clone()],
        )
        .expect("stray");
        assert_ne!(stray, "\0");
    }

    #[test]
    fn verify_stray_forces_failure_for_a_forcing_probe() {
        let ctx = build_stray_context("^a+$", Flags::default(), None);
        assert!(
            verify_stray_forces_failure(&ctx, "a", "\0").expect("verified"),
            "the NUL stray must force the anchored class to fail"
        );
    }

    #[test]
    fn stray_verification_timeout_honors_the_deadline() {
        let ctx = build_stray_context("abc", Flags::default(), None);
        assert_eq!(
            stray_verification_timeout(&ctx).expect("timeout"),
            STRAY_VERIFY_TIMEOUT_SECONDS
        );
        let expired = build_stray_context(
            "abc",
            Flags::default(),
            Some(Instant::now() - std::time::Duration::from_secs(1)),
        );
        let error = stray_verification_timeout(&expired).expect_err("expired");
        assert_eq!(
            error.0,
            "Pattern validation probe construction exceeded its deadline"
        );
    }

    #[test]
    fn leading_prefix_unwraps_only_complete_transparent_groups() {
        // A pattern that is exactly one transparent group unwraps to it.
        assert_eq!(leading_literal_prefix("(?:abc)"), "abc");
        // Trailing content stops the unwrap, and the paren is a metachar,
        // so no literal prefix remains.
        assert_eq!(leading_literal_prefix("(?:ab)c"), "");
        // An unclosed transparent group cannot be unwrapped either.
        assert_eq!(leading_literal_prefix("(?:abc"), "");
    }

    #[test]
    fn complement_chars_skip_fully_covered_pairings() {
        // A class covering every codepoint has an empty complement, so it
        // contributes no stray candidate.
        assert_eq!(
            pattern_complement_chars(r"[\x00-\U0010FFFF]", Flags::default()),
            Vec::<String>::new()
        );
        assert_eq!(
            pattern_complement_chars("x", Flags::default()),
            vec!["\0".to_owned()]
        );
    }

    #[test]
    fn bounded_forcing_candidate_maps_every_child_outcome() {
        let ctx = build_stray_context("abc", Flags::default(), None);
        let candidates = vec!["a".to_owned()];
        let probes = vec![vec!["aa".to_owned()]];
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Err(ChildSpawnError::Timeout)
            };
        let error = first_bounded_forcing_candidate_with(&ctx, &candidates, &probes, &runner)
            .expect_err("timeout");
        assert_eq!(
            error.0,
            "Pattern validation stray verification exceeded its \
             killable-subprocess timeout"
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Err(ChildSpawnError::Failed("spawn".to_owned()))
            };
        let error = first_bounded_forcing_candidate_with(&ctx, &candidates, &probes, &runner)
            .expect_err("spawn");
        assert_eq!(
            error.0,
            "Pattern validation stray verification killable-subprocess \
             failed to run (child failed: spawn)"
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Stray(Some("not-a-candidate".to_owned())))
            };
        let error = first_bounded_forcing_candidate_with(&ctx, &candidates, &probes, &runner)
            .expect_err("malformed");
        assert_eq!(
            error.0,
            "Pattern validation stray verification \
             killable-subprocess returned malformed output"
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Reference { reference: 0.5 })
            };
        let error = first_bounded_forcing_candidate_with(&ctx, &candidates, &probes, &runner)
            .expect_err("unexpected outcome");
        assert_eq!(
            error.0,
            "Pattern validation stray verification \
             killable-subprocess returned malformed output"
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Stray(Some("a".to_owned())))
            };
        assert_eq!(
            first_bounded_forcing_candidate_with(&ctx, &candidates, &probes, &runner)
                .expect("candidate"),
            Some("a".to_owned())
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Stray(None))
            };
        assert_eq!(
            first_bounded_forcing_candidate_with(&ctx, &candidates, &probes, &runner)
                .expect("none"),
            None
        );
    }

    #[test]
    fn repeat_probe_to_length_zero_is_empty() {
        // A zero-length probe has no last character to replace.
        assert_eq!(repeat_probe_to_length("abc", 0, "x"), "");
    }

    #[test]
    fn stray_for_pair_falls_back_when_the_union_covers_everything() {
        use crate::redos::intervals::IntervalSet;
        let full = IntervalSet::new(&[(0, char::MAX as u32)]);
        assert_eq!(stray_for_pair(&full, &full), "\u{0}");
    }

    #[test]
    #[should_panic(expected = "expected non-pairing")]
    fn expect_non_pairing_rejects_other_variants() {
        let pairing = Slot::Pairing(PairingAtom {
            intervals: crate::redos::intervals::IntervalSet::single(u32::from('a')),
            allows_zero: false,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        let _ = expect_non_pairing(&pairing);
    }

    #[test]
    #[should_panic(expected = "expected pairing")]
    fn expect_pairing_rejects_other_variants() {
        let non_pairing = Slot::NonPairing(NonPairingSlot {
            is_boundary: false,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        let _ = expect_pairing(&non_pairing);
    }
}
