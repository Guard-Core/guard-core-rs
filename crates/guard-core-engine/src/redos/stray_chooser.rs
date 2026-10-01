//! Stray character selection with child-verified forcing points.
//!
//! Port of the reference `_redos_stray_chooser.py`: candidates are only
//! ever verified against the untrusted pattern inside a killable child,
//! never inline.

use std::time::Instant;

use super::child::{run_child_request, ChildRequest, ChildSpawnError};
use super::intervals::IntervalSet;
use super::parse_slots::{pattern_slots, PairingAtom, Slot};
use super::structure::find_group_end;
use super::timeout::BuilderTimeout;

const REACH_PROBE_STRAY_BYTE: char = '\0';
const LEADING_PREFIX_METACHARS: &str = ".^$*+?{}[]()|\\";
const STRAY_FALLBACK_CANDIDATES: &[&str] = &[
    "\u{0}", "z", "\n", " ", "-", "\t", "\r", "9", "!", "~", "_", ".", "A", "\u{1f}",
    "\u{7f}", "/",
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
        if c == '\\'
            && i + 1 < n
            && !chars[i + 1].is_alphanumeric()
        {
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
        return format!(
            "{prefix}{}{stray}",
            fill_char.repeat(body_length - 1)
        );
    }
    format!("{prefix}{}", fill_char.repeat(body_length))
}

fn homogeneous_unit(unit: &str) -> bool {
    unit.chars().next().is_none_or(|first| {
        unit.chars().all(|c| c == first)
    })
}

/// Reference `_repeat_probe_to_length`.
#[must_use]
pub fn repeat_probe_to_length(unit: &str, length: usize, stray: &str) -> String {
    if unit.is_empty() {
        return unit.to_owned();
    }
    let unit_len = unit.chars().count();
    let mut result: Vec<char> = unit.chars().cycle().take(length).collect();
    if homogeneous_unit(unit) || length % unit_len == 0 {
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
    char::from_u32(member.unwrap_or(0)).map_or_else(
        || REACH_PROBE_STRAY_BYTE.to_string(),
        |c| c.to_string(),
    )
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

fn dedup_capped_candidates<I: IntoIterator<Item = Option<String>>>(
    candidates: I,
) -> Vec<String> {
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

fn stray_verification_timeout(
    ctx: &StrayContext,
) -> Result<f64, BuilderTimeout> {
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
    let timeout = stray_verification_timeout(ctx)?;
    let cases: Vec<(String, Vec<String>)> = candidates
        .iter()
        .cloned()
        .zip(probes.iter().cloned())
        .collect();
    let outcome = run_child_request(
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
    let mut ordered: Vec<Option<String>> =
        tail.iter().map(first_complement_char).collect();
    ordered.push(first_complement_char(right));
    ordered.push(first_complement_char(&left.union(right)));
    ordered.push(first_complement_char(pattern_union));
    ordered.extend(STRAY_FALLBACK_CANDIDATES.iter().map(|c| Some((*c).to_owned())));
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
    let candidates =
        class_intersection_stray_candidates(tail, left, right, &ctx.pattern_union);
    let probes = stray_verify_probes(ctx, fill_char, &candidates);
    let chosen = first_bounded_forcing_candidate(ctx, &candidates, &probes)?;
    Ok(chosen.unwrap_or_else(|| stray_for_pair(left, right)))
}

fn repeat_unit_stray_candidates(pattern_union: &IntervalSet) -> Vec<String> {
    let mut ordered: Vec<Option<String>> =
        vec![first_complement_char(pattern_union)];
    ordered.extend(STRAY_FALLBACK_CANDIDATES.iter().map(|c| Some((*c).to_owned())));
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
pub fn choose_repeat_unit_stray(
    ctx: &StrayContext,
    unit: &str,
) -> Result<String, BuilderTimeout> {
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
