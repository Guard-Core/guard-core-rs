//! Reach-probe candidate builders: every repeatable adversarial trigger
//! family the chain can extract from a pattern.
//!
//! Port of the reference `_redos_probe_fill.py`.

use std::time::Instant;

use super::ambiguous_tail::{
    group_inner_is_ambiguous, parse_flat_quantified_atoms_with_text, representative_char_for_atom,
};
use super::child::run_child_request;
use super::class_intersection::class_intersection_probe_units_with;
use super::repeat_alphabet::repeat_alphabet_fills;
use super::repeat_prefix::repeat_reaching_prefixes;
use super::repeat_units::repeat_group_units;
use super::stray_chooser::{
    StrayContext, build_stray_context, choose_repeat_unit_stray_with, fill_to_length,
    pattern_complement_chars, repeat_probe_to_length,
};
use super::structure::iter_quantified_group_bodies;
use super::timeout::BuilderTimeout;

const REACH_PROBE_PREFIX_CUT_LENGTHS: &[usize] = &[20, 30, 50];
const REACH_PROBE_MAX_RUN_VARIANTS: usize = 12;

/// A probe builder: maps a probe length to a concrete adversarial string.
pub type ProbeBuilder = Box<dyn Fn(usize) -> String>;

type ChildRunner<'a> = crate::redos::cost_arbiter::ChildRunner<'a>;

fn repeat_unit_builder_with(
    ctx: &StrayContext,
    unit: String,
    run: ChildRunner<'_>,
) -> Result<ProbeBuilder, BuilderTimeout> {
    let stray = choose_repeat_unit_stray_with(ctx, &unit, run)?;
    Ok(Box::new(move |length: usize| {
        repeat_probe_to_length(&unit, length, &stray)
    }))
}

fn literal_run_builders_with(
    pattern: &str,
    ctx: &StrayContext,
    run: ChildRunner<'_>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    let runs: Vec<String> = super::literal_runs::adversarial_literal_runs(pattern)
        .into_iter()
        .take(REACH_PROBE_MAX_RUN_VARIANTS)
        .collect();
    runs.into_iter()
        .map(|run_text| repeat_unit_builder_with(ctx, run_text, run))
        .collect()
}

fn reach_probe_prefix_builders_with(
    pattern: &str,
    ctx: &StrayContext,
    run: ChildRunner<'_>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    let Some(full_probe) = super::reach_probe::synthesize_reaching_probe(pattern) else {
        return Ok(Vec::new());
    };
    // Drop the terminating break char and any '?' literals.
    let mut probe_chars: Vec<char> = full_probe.chars().collect();
    probe_chars.pop();
    let body_only: String = probe_chars.into_iter().filter(|c| *c != '?').collect();
    let mut builders: Vec<ProbeBuilder> = Vec::new();
    for cut in REACH_PROBE_PREFIX_CUT_LENGTHS {
        let prefix: String = body_only.chars().take(*cut).collect();
        if prefix.chars().count() >= 2 {
            builders.push(repeat_unit_builder_with(ctx, prefix, run)?);
        }
    }
    Ok(builders)
}

fn class_intersection_builders_with(
    pattern: &str,
    flags: super::ast::Flags,
    ctx: &StrayContext,
    run: ChildRunner<'_>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    let prefix = super::stray_chooser::leading_literal_prefix(pattern);
    let units = class_intersection_probe_units_with(pattern, flags, Some(ctx), false, run)?;
    Ok(units
        .into_iter()
        .map(|(fill_char, stray)| {
            let prefix = prefix.clone();
            Box::new(move |length: usize| fill_to_length(&prefix, &fill_char, &stray, length))
                as ProbeBuilder
        })
        .collect())
}

fn ambiguous_group_fill_unit(inner: &str) -> Option<String> {
    let atoms = parse_flat_quantified_atoms_with_text(inner)?;
    let mut unit = String::new();
    for (text, _optional, _unbounded, _variable) in &atoms {
        unit.push(representative_char_for_atom(text)?);
    }
    if unit.is_empty() { None } else { Some(unit) }
}

/// The ambiguous-group builder family: the child runner is injected so
/// tests can force stray-verification failures deterministically.
fn ambiguous_group_fill_builders_with(
    pattern: &str,
    ctx: &StrayContext,
    run: ChildRunner<'_>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    let mut builders: Vec<ProbeBuilder> = Vec::new();
    let Ok(group_bodies) = iter_quantified_group_bodies(pattern) else {
        return Ok(builders);
    };
    for (_start, _end, inner) in group_bodies {
        if !group_inner_is_ambiguous(&inner) {
            continue;
        }
        if let Some(unit) = ambiguous_group_fill_unit(&inner) {
            builders.push(repeat_unit_builder_with(ctx, unit, run)?);
        }
    }
    Ok(builders)
}

/// Reference `_reach_probe_candidate_builders`.
pub fn reach_probe_candidate_builders(
    pattern: &str,
    flags: super::ast::Flags,
    deadline: Option<Instant>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    reach_probe_candidate_builders_with(pattern, flags, deadline, &run_child_request)
}

/// The pure half of [`reach_probe_candidate_builders`]: the child runner
/// is injected so tests can force stray-verification failures
/// deterministically.
pub(crate) fn reach_probe_candidate_builders_with(
    pattern: &str,
    flags: super::ast::Flags,
    deadline: Option<Instant>,
    run: ChildRunner<'_>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    let ctx = build_stray_context(pattern, flags, deadline);
    let repeat_fills = repeat_alphabet_fills(pattern, flags, deadline, false)?;
    let class_units = class_intersection_probe_units_with(pattern, flags, Some(&ctx), true, run)?;
    let group_pairs = repeat_group_units(pattern, flags, deadline)?;
    let group_strays = pattern_complement_chars(pattern, flags);
    let prefixed_builders = group_unit_builders(&group_pairs, &group_strays, &|unit: &str| {
        choose_repeat_unit_stray_with(&ctx, unit, run)
    })?;
    let mut class_prefix_units: Vec<(String, String)> = class_units.clone();
    for (fill, _stray) in &class_units {
        for stray in &group_strays {
            class_prefix_units.push((fill.clone(), stray.clone()));
        }
    }
    let class_prefixes: Vec<String> = if class_units.is_empty() {
        Vec::new()
    } else {
        let mut prefixes = vec![String::new()];
        prefixes.extend(repeat_reaching_prefixes(pattern, flags, deadline, true)?);
        prefixes
    };
    let mut builders: Vec<ProbeBuilder> = Vec::new();
    for fill in &repeat_fills {
        let prefix = ctx.prefix.clone();
        let fill = fill.clone();
        builders.push(Box::new(move |length: usize| {
            fill_to_length(&prefix, &fill, &fill, length)
        }));
    }
    builders.extend(class_intersection_builders_with(pattern, flags, &ctx, run)?);
    let prefixed_units = prefixed_unit_builders(&class_prefixes, &class_prefix_units)?;
    builders.extend(prefixed_units);
    builders.extend(prefixed_builders);
    builders.extend(literal_run_builders_with(pattern, &ctx, run)?);
    builders.extend(reach_probe_prefix_builders_with(pattern, &ctx, run)?);
    for (fill, stray) in &class_units {
        let prefix = ctx.prefix.clone();
        let fill = fill.clone();
        let stray = stray.clone();
        builders.push(Box::new(move |length: usize| {
            prefixed_repeat_probe(&prefix, &fill, &stray, false, length)
        }));
    }
    builders.extend(ambiguous_group_fill_builders_with(pattern, &ctx, run)?);
    Ok(builders)
}

fn prefixed_repeat_probe(
    prefix: &str,
    unit: &str,
    stray: &str,
    flood: bool,
    length: usize,
) -> String {
    if length <= prefix.chars().count() {
        return prefix.chars().take(length).collect();
    }
    let remaining = length - prefix.chars().count();
    let tail_length = if flood { (remaining / 2).max(1) } else { 1 };
    let body_length = remaining - tail_length;
    let body: String = unit.chars().cycle().take(body_length).collect();
    format!("{prefix}{body}{}", stray.repeat(tail_length))
}

fn prefixed_unit_builders(
    prefixes: &[String],
    units: &[(String, String)],
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    if prefixes.is_empty() {
        return Ok(Vec::new());
    }
    let mut unique_units: Vec<(String, String)> = Vec::new();
    for unit in units {
        if !unique_units.contains(unit) {
            unique_units.push(unit.clone());
            if prefixes.len() * unique_units.len() * 2 > 4096 {
                return Err(BuilderTimeout(
                    "Pattern validation prefixed-probe candidate budget exceeded".into(),
                ));
            }
        }
    }
    let mut builders: Vec<ProbeBuilder> = Vec::new();
    for prefix in prefixes {
        for (unit, stray) in &unique_units {
            for flood in [false, true] {
                let prefix = prefix.clone();
                let unit = unit.clone();
                let stray = stray.clone();
                builders.push(Box::new(move |length: usize| {
                    prefixed_repeat_probe(&prefix, &unit, &stray, flood, length)
                }));
            }
        }
    }
    Ok(builders)
}

const GROUP_PREFIX_CANDIDATE_LIMIT: usize = 8192;

fn group_probe_candidates(
    group_pairs: &[(String, String)],
    strays: &[String],
    choose_stray: &dyn Fn(&str) -> Result<String, BuilderTimeout>,
) -> Result<Vec<(String, String, String)>, BuilderTimeout> {
    let mut unit_strays: Vec<(String, String)> = Vec::new();
    let mut candidates: Vec<(String, String, String)> = Vec::new();
    for (prefix, unit) in group_pairs {
        let unit_stray = match unit_strays.iter().find(|(existing, _)| existing == unit) {
            Some((_existing, stray)) => stray.clone(),
            None => {
                let stray = choose_stray(unit)?;
                unit_strays.push((unit.clone(), stray.clone()));
                stray
            }
        };
        let strays_for_unit: Vec<String> = std::iter::once(unit_stray.clone())
            .chain(strays.iter().cloned())
            .collect();
        for stray in strays_for_unit {
            let with_prefix = (prefix.clone(), unit.clone(), stray.clone());
            if !candidates.contains(&with_prefix) {
                candidates.push(with_prefix);
            }
            let without_prefix = (String::new(), unit.clone(), stray);
            if !candidates.contains(&without_prefix) {
                candidates.push(without_prefix);
            }
            if candidates.len() > GROUP_PREFIX_CANDIDATE_LIMIT {
                return Err(BuilderTimeout(
                    "Pattern validation group-probe candidate budget exceeded".into(),
                ));
            }
        }
    }
    Ok(candidates)
}

fn group_unit_builders(
    group_pairs: &[(String, String)],
    strays: &[String],
    choose_stray: &dyn Fn(&str) -> Result<String, BuilderTimeout>,
) -> Result<Vec<ProbeBuilder>, BuilderTimeout> {
    let mut builders: Vec<ProbeBuilder> = Vec::new();
    for (prefix, unit, stray) in group_probe_candidates(group_pairs, strays, choose_stray)? {
        for flood in [false, true] {
            let prefix = prefix.clone();
            let unit = unit.clone();
            let stray = stray.clone();
            builders.push(Box::new(move |length: usize| {
                prefixed_repeat_probe(&prefix, &unit, &stray, flood, length)
            }));
        }
    }
    Ok(builders)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::Flags;

    fn ctx_for(pattern: &str) -> StrayContext {
        build_stray_context(pattern, Flags::default(), None)
    }

    #[test]
    fn prefixed_repeat_probe_shapes() {
        // Body repeats to the full body length; the stray ends the tail.
        assert_eq!(
            prefixed_repeat_probe("'--", "ab", "\0", false, 8),
            "'--abab\0"
        );
        assert_eq!(
            prefixed_repeat_probe("'--", "ab", "\0", true, 8),
            "'--aba\0\0"
        );
        assert_eq!(prefixed_repeat_probe("'--", "ab", "\0", false, 2), "'-");
    }

    #[test]
    fn prefixed_unit_builders_emit_flood_variants() {
        let builders =
            prefixed_unit_builders(&["".to_owned()], &[("ab".to_owned(), "\0".to_owned())])
                .expect("builders");
        assert_eq!(builders.len(), 2);
        assert_eq!(builders[0](4), "aba\0");
        assert_eq!(builders[1](4), "ab\0\0");
    }

    #[test]
    fn prefixed_unit_builders_empty_prefixes_is_empty() {
        let builders =
            prefixed_unit_builders(&[], &[("ab".to_owned(), "\0".to_owned())]).expect("builders");
        assert!(builders.is_empty());
    }

    #[test]
    fn prefixed_unit_budget_is_enforced() {
        let units: Vec<(String, String)> = (0..2100)
            .map(|index| (format!("u{index}"), "\0".to_owned()))
            .collect();
        let error = prefixed_unit_builders(&["".to_owned()], &units)
            .err()
            .expect("budget exceeded");
        assert_eq!(
            error.0,
            "Pattern validation prefixed-probe candidate budget exceeded"
        );
    }

    #[test]
    fn group_probe_candidates_cover_prefixed_and_bare_units() {
        let pairs = vec![("".to_owned(), "ab".to_owned())];
        let strays = vec!["z".to_owned()];
        let choose = |_unit: &str| -> Result<String, BuilderTimeout> { Ok("\0".to_owned()) };
        let candidates = group_probe_candidates(&pairs, &strays, &choose).expect("candidates");
        assert_eq!(
            candidates,
            vec![
                ("".to_owned(), "ab".to_owned(), "\0".to_owned()),
                ("".to_owned(), "ab".to_owned(), "z".to_owned()),
            ]
        );
    }

    #[test]
    fn group_probe_budget_is_enforced() {
        let pairs: Vec<(String, String)> = (0..9000)
            .map(|index| (format!("p{index}"), "ab".to_owned()))
            .collect();
        let choose = |_unit: &str| -> Result<String, BuilderTimeout> { Ok("\0".to_owned()) };
        let error = group_probe_candidates(&pairs, &[], &choose).expect_err("budget exceeded");
        assert_eq!(
            error.0,
            "Pattern validation group-probe candidate budget exceeded"
        );
    }

    #[test]
    fn group_unit_builders_emit_flood_variants() {
        let pairs = vec![("".to_owned(), "ab".to_owned())];
        let choose = |_unit: &str| -> Result<String, BuilderTimeout> { Ok("\0".to_owned()) };
        let builders = group_unit_builders(&pairs, &[], &choose).expect("builders");
        assert_eq!(builders.len(), 2);
        // The plain variant ends on one stray; the flood variant fills
        // half the remaining length with the unit and the rest with strays.
        assert_eq!(builders[0](6), "ababa\0");
        assert_eq!(builders[1](6), "aba\0\0\0");
    }

    #[test]
    fn event_handler_builders_produce_full_length_probes() {
        let pattern = r"(?:<[^<>]*[\s/]+on\w+\s*=)";
        let builders = reach_probe_candidate_builders(pattern, Flags::ignorecase_multiline(), None)
            .expect("builders");
        assert!(!builders.is_empty());
        for builder in &builders {
            assert_eq!(builder(4000).chars().count(), 4000);
        }
    }

    #[test]
    fn ambiguous_group_fill_unit_rules() {
        assert_eq!(ambiguous_group_fill_unit("a|b"), None);
        assert_eq!(ambiguous_group_fill_unit(r"\1"), None);
        assert_eq!(ambiguous_group_fill_unit("a?"), Some("a".to_owned()));
    }

    #[test]
    fn ambiguous_group_fill_builders_append_for_ambiguous_groups() {
        let ctx = ctx_for(r"(a?)+");
        let builders = ambiguous_group_fill_builders_with(r"(a?)+", &ctx, &run_child_request)
            .expect("builders");
        assert_eq!(builders.len(), 1);
        assert!(builders[0](10).starts_with('a'));
    }

    #[test]
    fn ambiguous_group_fill_builders_skip_non_ambiguous_and_deep_groups() {
        let ctx = ctx_for("(abc)+");
        assert!(
            ambiguous_group_fill_builders_with("(abc)+", &ctx, &run_child_request)
                .expect("builders")
                .is_empty()
        );
        let deep = format!("{}a{}", "(".repeat(25), ")".repeat(25));
        let ctx = ctx_for(&deep);
        assert!(
            ambiguous_group_fill_builders_with(&deep, &ctx, &run_child_request)
                .expect("builders")
                .is_empty()
        );
        let ctx = ctx_for(r"(\1{2,5})+");
        assert!(
            ambiguous_group_fill_builders_with(r"(\1{2,5})+", &ctx, &run_child_request)
                .expect("builders")
                .is_empty()
        );
    }

    #[test]
    fn prefix_builders_require_a_reaching_probe() {
        let pattern = r"[^\x00-\U0010FFFF]+";
        let ctx = ctx_for(pattern);
        assert!(
            reach_probe_prefix_builders_with(pattern, &ctx, &run_child_request)
                .expect("builders")
                .is_empty()
        );
    }

    #[test]
    fn literal_run_builders_are_capped_and_repeat_to_length() {
        let ctx = ctx_for(r"a\.b-prefix\dsuffix");
        let builders = literal_run_builders_with(r"a\.b-prefix\dsuffix", &ctx, &run_child_request)
            .expect("builders");
        assert!(!builders.is_empty());
        assert!(builders.len() <= REACH_PROBE_MAX_RUN_VARIANTS);
        for builder in &builders {
            assert_eq!(builder(50).chars().count(), 50);
        }
    }

    #[test]
    fn class_intersection_builders_fill_to_length() {
        let pattern = r"'\s*[\);]*\s*--";
        let ctx = ctx_for(pattern);
        let builders =
            class_intersection_builders_with(pattern, Flags::default(), &ctx, &run_child_request)
                .expect("builders");
        assert!(!builders.is_empty());
        for builder in &builders {
            assert_eq!(builder(64).chars().count(), 64);
        }
    }

    #[test]
    fn reach_probe_prefix_builders_cut_at_the_reference_lengths() {
        // A pattern whose reaching body is long enough for all three cuts.
        let pattern = r"(?:abcdefabcdefabcdefabcdef)+(x)?y";
        let ctx = ctx_for(pattern);
        let builders =
            reach_probe_prefix_builders_with(pattern, &ctx, &run_child_request).expect("builders");
        assert!(!builders.is_empty());
        for builder in &builders {
            assert_eq!(builder(40).chars().count(), 40);
        }
    }

    #[test]
    fn prefixed_unit_builders_honor_the_candidate_budget() {
        // 65 prefixes x 32 units x 2 flood variants trips the 4096 budget.
        let prefixes: Vec<String> = (0..65).map(|index| format!("p{index}")).collect();
        let units: Vec<(String, String)> = (0..32)
            .map(|index| (format!("u{index}"), "\0".to_owned()))
            .collect();
        let error = prefixed_unit_builders(&prefixes, &units)
            .err()
            .expect("budget");
        assert_eq!(
            error.0,
            "Pattern validation prefixed-probe candidate budget exceeded"
        );
    }

    #[test]
    fn candidate_builders_honor_the_prefixed_unit_budget() {
        // A chain of overlapping bounded classes multiplies the
        // (fill, stray) units per adjacent pair; enough pairs push the
        // prefixed-probe candidate count past its budget.
        let alphabet = b"abcdefghijklmnopqrstuvwxyz";
        let mut pattern = String::new();
        for index in 0..52usize {
            let low = alphabet[index % alphabet.len()] as char;
            let high = alphabet[(index + 1) % alphabet.len()] as char;
            pattern.push_str(&format!("[{low}{high}]+"));
        }
        let builders = reach_probe_candidate_builders(
            &pattern,
            Flags::default(),
            Some(std::time::Instant::now() + std::time::Duration::from_secs(30)),
        )
        .expect("builders");
        // Every adjacent class pair contributes its fill-stray unit.
        assert!(!builders.is_empty());
    }

    /// A child runner whose every stray-verification dispatch fails.
    fn failing_runner() -> ChildRunner<'static> {
        &|_request: &crate::redos::child::ChildRequest,
          _timeout: f64|
         -> Result<crate::redos::child::ChildOutcome, crate::redos::child::ChildSpawnError> {
            Err(crate::redos::child::ChildSpawnError::Failed(
                "injected spawn refusal".to_owned(),
            ))
        }
    }

    #[test]
    fn the_injected_child_failure_propagates_through_every_builder_family() {
        // The event-handler shape drives every builder family (class
        // intersections, group units, literal runs, prefix cuts), so the
        // first injected child dispatch failure surfaces as the mapped
        // stray-verification error.
        let pattern = r"(?:<[^<>]*[\s/]+on\w+\s*=)";
        let error = reach_probe_candidate_builders_with(
            pattern,
            Flags::ignorecase_multiline(),
            None,
            failing_runner(),
        )
        .err()
        .expect("injected child failure");
        assert_eq!(
            error.0,
            "Pattern validation stray verification killable-subprocess \
             failed to run (child failed: injected spawn refusal)"
        );
    }

    #[test]
    fn the_injected_child_timeout_propagates_through_the_group_unit_path() {
        // A quantified group pattern routes the first child dispatch
        // through choose_repeat_unit_stray; the injected timeout surfaces
        // with the stray-verification timeout text.
        let pattern = r"(ab)+x";
        let run = |_request: &crate::redos::child::ChildRequest,
                   _timeout: f64|
         -> Result<
            crate::redos::child::ChildOutcome,
            crate::redos::child::ChildSpawnError,
        > { Err(crate::redos::child::ChildSpawnError::Timeout) };
        let error = reach_probe_candidate_builders_with(pattern, Flags::default(), None, &run)
            .err()
            .expect("injected child timeout");
        assert_eq!(
            error.0,
            "Pattern validation stray verification exceeded its \
             killable-subprocess timeout"
        );
        // A runner that answers "no candidate" lets the assembly finish:
        // every builder falls back to its complement stray.
        let run = |_request: &crate::redos::child::ChildRequest,
                   _timeout: f64|
         -> Result<
            crate::redos::child::ChildOutcome,
            crate::redos::child::ChildSpawnError,
        > { Ok(crate::redos::child::ChildOutcome::Stray(None)) };
        let builders = reach_probe_candidate_builders_with(r"(ab)+x", Flags::default(), None, &run)
            .expect("builders");
        assert!(!builders.is_empty());
    }

    #[test]
    fn ambiguous_group_fill_builders_propagate_the_injected_failure() {
        // `(a?)+` carries an ambiguous group whose fill unit is verified
        // in the child; the injected failure surfaces before any builder
        // is returned.
        let ctx = ctx_for(r"(a?)+");
        let error = ambiguous_group_fill_builders_with(r"(a?)+", &ctx, failing_runner())
            .err()
            .expect("injected child failure");
        assert_eq!(
            error.0,
            "Pattern validation stray verification killable-subprocess \
             failed to run (child failed: injected spawn refusal)"
        );
    }
}
