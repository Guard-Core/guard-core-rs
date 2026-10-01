//! The empirical cost arbiter: budget ladder, host-load normalization,
//! stride sampling, and retry-once verdicts over killable timing children.
//!
//! Port of the reference `_redos_cost_arbiter.py`. The reference constant
//! `_REFERENCE_SCAN_SECONDS` (0.00229s) was calibrated against the Python
//! engine; the port recalibrates it once per process by measuring the same
//! reference scan under the Rust `regex` engine in a probe child (see
//! [`reference_scan_seconds`]) and falls back to the reference value when
//! the measurement fails.

use std::sync::LazyLock;
use std::time::Instant;

use super::child::{ChildOutcome, ChildRequest, ChildSpawnError, run_child_request};
use super::prefilters::first_structural_safety_violation;
use super::probe_batches::{
    REACH_PROBE_BATCH_SIZE, ReachProbeTiming, decode_reach_timing, probe_set_digest,
    valid_timing_rows,
};
use super::probe_fill::reach_probe_candidate_builders;
use super::reach_probe::synthesize_reaching_probe;
use super::repeat_alphabet::has_large_bounded_repeat;
use super::timeout::BuilderTimeout;

/// Kill timeout for the pattern-safety (test-strings) child.
pub const PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS: f64 = 2.0;
/// Per-string CPU threshold for the pattern-safety child.
pub const PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS: f64 = 0.05;
/// Reach-probe sizes (the budget ladder).
pub const REACH_PROBE_SIZES: &[usize] = &[4000, 8000, 16000, 32000];
/// Verdict-mode probe sizes (the last two rungs).
pub fn reach_verdict_probe_sizes() -> Vec<usize> {
    REACH_PROBE_SIZES[REACH_PROBE_SIZES.len() - 2..].to_vec()
}
/// The safety budget the extrapolated cost must stay under.
pub const REACH_PROBE_BUDGET_SECONDS: f64 = 0.05;
/// The reference-engine reference scan seconds (fallback constant).
pub const REFERENCE_SCAN_FALLBACK_SECONDS: f64 = 0.00229;
/// Load factor clamp floor.
pub const LOAD_FACTOR_FLOOR: f64 = 0.25;
/// Load factor clamp ceiling.
pub const LOAD_FACTOR_CEILING: f64 = 8.0;
/// Samples below this read as noise.
pub const REACH_PROBE_NOISE_FLOOR_SECONDS: f64 = 0.001;
/// Sample count per probe.
pub const REACH_PROBE_SAMPLE_COUNT: usize = 5;
/// The full-sample trigger equals the noise floor.
pub const REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS: f64 = REACH_PROBE_NOISE_FLOOR_SECONDS;
/// Default max content length when unset.
pub const PATTERN_SAFETY_DEFAULT_CAP: usize = 262_144;
/// Stride-sample cap on timed probe sets.
pub const MAX_TIMED_PROBE_SETS: usize = 512;
/// Deadline scale ceiling under heavy host load.
pub const REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS: f64 = 240.0;
/// Timeout for the one-shot reference load probe.
pub const REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS: f64 = 5.0;
/// Child start allowance on top of the pattern-safety timeout.
const REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS: f64 = 0.5;
/// Timeout for a single-probe timing child.
pub const REACH_PROBE_CHILD_TIMEOUT_SECONDS: f64 =
    PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS + REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS;
/// Timeout for a whole combined-ladder timing child.
pub fn reach_probe_combined_timeout_seconds() -> f64 {
    PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS
        * REACH_PROBE_SIZES.len() as f64
        * REACH_PROBE_SAMPLE_COUNT as f64
}

/// The recalibrated reference scan constant: measured once on first use
/// under the Rust regex engine, falling back to the reference value.
pub fn reference_scan_seconds() -> f64 {
    static MEASURED: LazyLock<f64> = LazyLock::new(|| measured_reference_scan(&run_child_request));
    *MEASURED
}

/// The pure half of [`reference_scan_seconds`], injectable for tests.
fn measured_reference_scan(run: ChildRunner<'_>) -> f64 {
    match run(
        &ChildRequest::ReferenceLoad,
        REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS,
    ) {
        Ok(ChildOutcome::Reference { reference }) if reference > 0.0 => reference,
        _ => REFERENCE_SCAN_FALLBACK_SECONDS,
    }
}

/// A killable child runner, injectable for deterministic tests.
pub(crate) type ChildRunner<'a> =
    &'a dyn Fn(&ChildRequest, f64) -> Result<ChildOutcome, ChildSpawnError>;

/// Reference `_load_factor`.
#[must_use]
pub fn load_factor(reference_seconds: f64) -> f64 {
    (reference_seconds / reference_scan_seconds()).clamp(LOAD_FACTOR_FLOOR, LOAD_FACTOR_CEILING)
}

/// Host load factor measured in a killable child; fails open to 1.0.
#[must_use]
pub fn measure_host_load_factor() -> f64 {
    measured_host_load_factor(&run_child_request)
}

/// The pure half of [`measure_host_load_factor`], injectable for tests.
fn measured_host_load_factor(run: ChildRunner<'_>) -> f64 {
    match run(
        &ChildRequest::ReferenceLoad,
        REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS,
    ) {
        Ok(ChildOutcome::Reference { reference }) => load_factor(reference),
        _ => 1.0,
    }
}

/// Reference `_scaled_probe_deadline_seconds`.
#[must_use]
pub fn scaled_probe_deadline_seconds(load: f64) -> f64 {
    (reach_probe_combined_timeout_seconds() * load.max(1.0))
        .min(REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS)
}

fn remaining_budget(deadline: Instant) -> f64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_secs_f64()
}

fn clipped_timeout(default_timeout: f64, deadline: Instant) -> f64 {
    default_timeout.min(remaining_budget(deadline))
}

fn run_timing_child(
    pattern: &str,
    probes: Vec<String>,
    timeout: f64,
    flags: super::ast::Flags,
) -> Option<ReachProbeTiming> {
    let outcome = run_child_request(
        &ChildRequest::ReachTiming {
            pattern: pattern.to_owned(),
            probes,
            samples: REACH_PROBE_SAMPLE_COUNT,
            deadline: timeout,
            flags,
            trigger: REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS,
        },
        timeout,
    );
    let decoded = decode_reach_timing(outcome.as_ref().ok())?;
    let (rows, reference) = decoded;
    Some(ReachProbeTiming {
        samples_by_size: rows,
        load_factor: load_factor(reference),
    })
}

/// Combined-ladder timing: one child measures every probe.
pub fn time_reach_probes_subprocess(
    pattern: &str,
    probes: Vec<String>,
    deadline: Instant,
    flags: super::ast::Flags,
) -> Option<ReachProbeTiming> {
    let timeout = clipped_timeout(reach_probe_combined_timeout_seconds(), deadline);
    if timeout <= 0.0 {
        return None;
    }
    run_timing_child(pattern, probes, timeout, flags)
}

/// Single-probe timing child.
pub fn time_single_reach_probe_subprocess(
    pattern: &str,
    probe: String,
    deadline: Instant,
    flags: super::ast::Flags,
) -> Option<ReachProbeTiming> {
    let timeout = clipped_timeout(REACH_PROBE_CHILD_TIMEOUT_SECONDS, deadline);
    if timeout <= 0.0 {
        return None;
    }
    run_timing_child(pattern, vec![probe], timeout, flags)
}

/// Ascending timing: one child per probe, smallest sizes first; used for
/// structural-violation and bounded-repeat-risk patterns.
pub fn time_reach_probes_ascending(
    pattern: &str,
    probes: Vec<String>,
    deadline: Instant,
    flags: super::ast::Flags,
) -> Option<ReachProbeTiming> {
    let mut samples_by_size: Vec<Vec<f64>> = Vec::new();
    let mut load_factor_min = LOAD_FACTOR_CEILING;
    for probe in probes {
        let timing = time_single_reach_probe_subprocess(pattern, probe, deadline, flags)?;
        samples_by_size.extend(timing.samples_by_size);
        load_factor_min = load_factor_min.min(timing.load_factor);
    }
    Some(ReachProbeTiming {
        samples_by_size,
        load_factor: load_factor_min,
    })
}

/// The timing strategy signature.
pub type TimeProbes<'a> =
    &'a dyn Fn(&str, Vec<String>, Instant, super::ast::Flags) -> Option<ReachProbeTiming>;

pub(crate) enum TimingStrategy {
    Combined,
    Ascending,
}

fn timing_strategy(
    structural_violation: Option<&str>,
    bounded_repeat_risk: bool,
) -> TimingStrategy {
    if structural_violation.is_some() || bounded_repeat_risk {
        TimingStrategy::Ascending
    } else {
        TimingStrategy::Combined
    }
}

fn reach_probe_sizes_for_strategy(
    structural_violation: Option<&str>,
    bounded_repeat_risk: bool,
) -> Vec<usize> {
    if structural_violation.is_some() || bounded_repeat_risk {
        REACH_PROBE_SIZES.to_vec()
    } else {
        reach_verdict_probe_sizes()
    }
}

fn run_with_strategy(
    strategy: &TimingStrategy,
    pattern: &str,
    probes: Vec<String>,
    deadline: Instant,
    flags: super::ast::Flags,
) -> Option<ReachProbeTiming> {
    match strategy {
        TimingStrategy::Combined => time_reach_probes_subprocess(pattern, probes, deadline, flags),
        TimingStrategy::Ascending => time_reach_probes_ascending(pattern, probes, deadline, flags),
    }
}

/// The structured over-budget verdict payload.
#[derive(Debug, Clone, PartialEq)]
pub struct OverBudget {
    pub cap: usize,
    pub extrapolated: f64,
    pub ratio: f64,
    pub min_32: f64,
    pub median_32: f64,
    pub load_factor: f64,
}

/// Reference `_reach_probe_verdict_from_samples`.
#[must_use]
pub fn reach_probe_verdict_from_samples(
    samples_by_size: &[Vec<f64>],
    cap: usize,
    load: f64,
) -> (bool, OverBudget) {
    fn median(samples: &[f64]) -> f64 {
        samples[samples.len() / 2]
    }
    let last = &samples_by_size[samples_by_size.len() - 1];
    let second_last = &samples_by_size[samples_by_size.len() - 2];
    let median_32 = median(last) / load;
    let min_16 = second_last[0] / load;
    let min_32 = last[0] / load;
    let ratio = if min_16 > REACH_PROBE_NOISE_FLOOR_SECONDS {
        (min_32 / min_16).max(1.0)
    } else {
        1.0
    };
    let doublings = (cap.max(1) as f64 / REACH_PROBE_SIZES[3] as f64).log2();
    let extrapolated = min_32 * ratio.powf(doublings);
    (
        extrapolated > REACH_PROBE_BUDGET_SECONDS,
        OverBudget {
            cap,
            extrapolated,
            ratio,
            min_32,
            median_32,
            load_factor: load,
        },
    )
}

/// The human-readable over-budget reason (reference `_reach_probe_cost_reason`).
#[must_use]
pub fn reach_probe_cost_reason(structural_violation: Option<&str>, over: &OverBudget) -> String {
    if let Some(violation) = structural_violation {
        return violation.to_owned();
    }
    format!(
        "Pattern extrapolated CPU cost at cap ({} chars) is {:.3}s, exceeding \
         the {:.2}s safety budget (growth ratio {:.2}x per doubling, CPU time \
         at 32000 chars: min {:.4}s, median {:.4}s over {} runs, normalized by \
         host load factor {:.2})",
        over.cap,
        over.extrapolated,
        REACH_PROBE_BUDGET_SECONDS,
        over.ratio,
        over.min_32,
        over.median_32,
        REACH_PROBE_SAMPLE_COUNT,
        over.load_factor,
    )
}

/// Reference `_reach_probe_unreachable_reason`.
#[must_use]
pub fn reach_probe_unreachable_reason(structural_violation: Option<&str>) -> String {
    if let Some(violation) = structural_violation {
        return violation.to_owned();
    }
    "Pattern validation probe could not construct a test string that \
     reaches every quantified region of this pattern; rejecting rather \
     than certifying safety on an unreachable probe"
        .to_owned()
}

/// The structured outcome of a cost-verdict run.
#[derive(Debug, Clone, PartialEq)]
pub enum CostOutcome {
    /// Certified safe under budget.
    Safe,
    /// Rejected by extrapolated cost.
    Over(OverBudget),
    /// No reaching probe could be synthesized.
    Unreachable,
    /// The structural violation stands (echoed in the reason).
    Structural,
    /// Probe construction exceeded its deadline.
    BuilderDeadline(String),
}

fn unique_probe_sets(
    builders: &[super::probe_fill::ProbeBuilder],
    probe_sizes: &[usize],
) -> Vec<Vec<String>> {
    let mut seen: Vec<[u8; 32]> = Vec::new();
    let mut sets: Vec<Vec<String>> = Vec::new();
    for builder in builders {
        let probes: Vec<String> = probe_sizes.iter().map(|size| builder(*size)).collect();
        let digest = probe_set_digest(&probes);
        if seen.contains(&digest) {
            continue;
        }
        seen.push(digest);
        sets.push(probes);
    }
    sets
}

fn stride_sampled_probe_sets(probe_sets: Vec<Vec<String>>, cap: usize) -> Vec<Vec<String>> {
    let total = probe_sets.len();
    if total <= cap {
        return probe_sets;
    }
    let stride = total.div_ceil(cap);
    probe_sets.into_iter().step_by(stride).collect()
}

/// Reference `_reach_probe_cost_verdict`.
#[must_use]
pub fn reach_probe_cost_verdict(
    pattern: &str,
    max_content_length: Option<usize>,
    flags: super::ast::Flags,
) -> CostOutcome {
    let deadline = Instant::now()
        + std::time::Duration::from_secs_f64(scaled_probe_deadline_seconds(
            measure_host_load_factor(),
        ));
    let structural_violation = first_structural_safety_violation(pattern);
    let bounded_repeat_risk = has_large_bounded_repeat(pattern, flags);
    let run: TimeProbes<'_> = &|_pattern, probes, dl, fl| {
        run_with_strategy(
            &timing_strategy(structural_violation.as_deref(), bounded_repeat_risk),
            pattern,
            probes,
            dl,
            fl,
        )
    };
    reach_probe_cost_verdict_with_deadline(pattern, max_content_length, flags, deadline, run)
}

/// The pure half of [`reach_probe_cost_verdict`]: the deadline and the
/// timing strategy are injected so tests can force every arm
/// deterministically.
pub(crate) fn reach_probe_cost_verdict_with_deadline(
    pattern: &str,
    max_content_length: Option<usize>,
    flags: super::ast::Flags,
    deadline: Instant,
    time_probes: TimeProbes<'_>,
) -> CostOutcome {
    let cap = max_content_length
        .filter(|length| *length > 0)
        .unwrap_or(PATTERN_SAFETY_DEFAULT_CAP);
    let structural_violation = first_structural_safety_violation(pattern);
    let bounded_repeat_risk = has_large_bounded_repeat(pattern, flags);
    if synthesize_reaching_probe(pattern).is_none() {
        return CostOutcome::Unreachable;
    }
    let builders = match reach_probe_candidate_builders(pattern, flags, Some(deadline)) {
        Ok(builders) => builders,
        Err(BuilderTimeout(message)) => {
            return CostOutcome::BuilderDeadline(structural_violation.unwrap_or(message));
        }
    };
    if remaining_budget(deadline) <= 0.0 {
        return CostOutcome::BuilderDeadline(
            "Pattern validation probe construction exceeded its deadline".into(),
        );
    }
    if builders.is_empty() {
        return CostOutcome::Safe;
    }
    if let Some(over) = first_over_budget_reason_with(
        pattern,
        &builders,
        cap,
        structural_violation.as_deref(),
        deadline,
        flags,
        bounded_repeat_risk,
        time_probes,
    ) {
        return over;
    }
    CostOutcome::Safe
}

#[allow(clippy::too_many_arguments)]
fn first_over_budget_reason_with(
    pattern: &str,
    builders: &[super::probe_fill::ProbeBuilder],
    cap: usize,
    structural_violation: Option<&str>,
    deadline: Instant,
    flags: super::ast::Flags,
    bounded_repeat_risk: bool,
    time_probes: TimeProbes<'_>,
) -> Option<CostOutcome> {
    let probe_sizes = reach_probe_sizes_for_strategy(structural_violation, bounded_repeat_risk);
    let probe_sets = stride_sampled_probe_sets(
        unique_probe_sets(builders, &probe_sizes),
        MAX_TIMED_PROBE_SETS,
    );
    let run = |probes: Vec<String>| time_probes(pattern, probes, deadline, flags);
    if structural_violation.is_none()
        && !bounded_repeat_risk
        && builders.len() >= REACH_PROBE_BATCH_SIZE
    {
        // Batched mode: one child per batch of probe sets, sliced back per
        // set; the first over-budget set stops the walk (the reference
        // streams batches lazily).
        for batch in probe_sets.chunks(REACH_PROBE_BATCH_SIZE) {
            let flattened: Vec<String> = batch.concat();
            let validated = valid_timing_rows(run(flattened.clone()).as_ref(), flattened.len());
            let Some((rows, load)) = validated else {
                return batch_timeout_outcome(structural_violation);
            };
            let mut offset = 0usize;
            for probes in batch {
                let next_offset = offset + probes.len();
                if let Some(outcome) = verdict_for_set(
                    probes,
                    &rows[offset..next_offset],
                    load,
                    cap,
                    deadline,
                    &run,
                ) {
                    return Some(outcome);
                }
                offset = next_offset;
            }
        }
        return None;
    }
    for probes in probe_sets {
        let validated = valid_timing_rows(run(probes.clone()).as_ref(), probes.len());
        let Some((rows, load)) = validated else {
            return batch_timeout_outcome(structural_violation);
        };
        if let Some(outcome) = verdict_for_set(&probes, &rows, load, cap, deadline, &run) {
            return Some(outcome);
        }
    }
    None
}

fn batch_timeout_outcome(structural_violation: Option<&str>) -> Option<CostOutcome> {
    Some(match structural_violation {
        Some(_) => CostOutcome::Structural,
        None => CostOutcome::BuilderDeadline(
            "Pattern validation probe exceeded the killable-subprocess \
             timeout while measuring reach-probe cost at scale"
                .into(),
        ),
    })
}

fn verdict_for_set(
    probes: &[String],
    rows: &[Vec<f64>],
    load: f64,
    cap: usize,
    deadline: Instant,
    time_probes: &dyn Fn(Vec<String>) -> Option<ReachProbeTiming>,
) -> Option<CostOutcome> {
    let (mut over, mut over_budget) = reach_probe_verdict_from_samples(rows, cap, load);
    if over && remaining_budget(deadline) > 0.0 {
        let retry = valid_timing_rows(time_probes(probes.to_vec()).as_ref(), probes.len());
        if let Some((retry_rows, retry_load)) = retry {
            let (retry_over, retry_budget) =
                reach_probe_verdict_from_samples(&retry_rows, cap, retry_load);
            over = retry_over;
            over_budget = retry_budget;
        }
    }
    over.then_some(CostOutcome::Over(over_budget))
}

/// The pattern-safety (test-strings) probe: structural check plus the
/// timed child (reference `_run_pattern_safety_probe_subprocess`).
#[derive(Debug, Clone, PartialEq)]
pub enum TestStringsOutcome {
    /// Every test string searched under the per-string threshold.
    Safe,
    /// The child reported the first slow string.
    SlowString(usize),
    /// The child failed to compile the pattern.
    CompileFailed(String),
    /// The child was killed by the 2.0s deadline.
    SubprocessTimeout,
    /// The child failed to spawn or exited unexpectedly.
    SpawnFailed(String),
}

pub(crate) fn run_pattern_safety_probe(
    pattern: &str,
    test_strings: Vec<String>,
    flags: super::ast::Flags,
) -> TestStringsOutcome {
    run_pattern_safety_probe_with(pattern, test_strings, flags, &run_child_request)
}

/// The pure half of [`run_pattern_safety_probe`]: the child runner is
/// injected so tests can force every outcome deterministically.
pub(crate) fn run_pattern_safety_probe_with(
    pattern: &str,
    test_strings: Vec<String>,
    flags: super::ast::Flags,
    run: ChildRunner<'_>,
) -> TestStringsOutcome {
    let outcome = run(
        &ChildRequest::TestStrings {
            pattern: pattern.to_owned(),
            test_strings,
            threshold: PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS,
            flags,
        },
        PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS,
    );
    match outcome {
        Err(ChildSpawnError::Timeout) => TestStringsOutcome::SubprocessTimeout,
        Err(ChildSpawnError::Failed(detail)) => TestStringsOutcome::SpawnFailed(detail),
        Ok(ChildOutcome::Failed(message)) => TestStringsOutcome::CompileFailed(message),
        Ok(ChildOutcome::Safety { safe, reason }) => {
            if safe {
                TestStringsOutcome::Safe
            } else if let Some(length) = reason
                .strip_prefix("Pattern timed out on test string of length ")
                .and_then(|tail| tail.parse().ok())
            {
                TestStringsOutcome::SlowString(length)
            } else {
                TestStringsOutcome::CompileFailed(reason)
            }
        }
        Ok(_) => TestStringsOutcome::SpawnFailed("unexpected child outcome".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::Flags;

    #[test]
    fn load_factor_is_one_on_the_reference_host() {
        // The recalibrated constant is the measured reference scan, so a
        // measurement equal to it reads as load 1.0.
        let reference = reference_scan_seconds();
        assert!((load_factor(reference) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn load_factor_clamps_to_floor_and_ceiling() {
        assert!((load_factor(0.0) - LOAD_FACTOR_FLOOR).abs() < 1e-9);
        assert!((load_factor(f64::INFINITY) - LOAD_FACTOR_CEILING).abs() < 1e-9);
        assert!((load_factor(0.00229 * 1000.0) - LOAD_FACTOR_CEILING).abs() < 1e-9);
    }

    #[test]
    fn reference_scan_constant_is_sane() {
        // The recalibrated constant must sit in a plausible band for a
        // single 32K reference scan.
        let reference = reference_scan_seconds();
        assert!(
            reference > 0.0 && reference < 1.0,
            "reference scan seconds out of band: {reference}"
        );
    }

    #[test]
    fn scaled_deadline_scales_with_load_and_respects_the_ceiling() {
        let combined = reach_probe_combined_timeout_seconds();
        assert_eq!(scaled_probe_deadline_seconds(LOAD_FACTOR_FLOOR), combined);
        assert!((scaled_probe_deadline_seconds(1.0) - combined).abs() < 1e-9);
        assert!((scaled_probe_deadline_seconds(2.0) - 2.0 * combined).abs() < 1e-9);
        assert_eq!(
            scaled_probe_deadline_seconds(LOAD_FACTOR_CEILING),
            REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS
        );
        assert_eq!(reach_verdict_probe_sizes(), vec![16000, 32000]);
    }

    #[test]
    fn verdict_math_extrapolates_down_for_a_small_cap() {
        let linear = vec![
            vec![0.001; 5],
            vec![0.002; 5],
            vec![0.004; 5],
            vec![0.008; 5],
        ];
        let (over, over_budget) = reach_probe_verdict_from_samples(&linear, 512, 1.0);
        assert!(!over);
        assert!((over_budget.ratio - 2.0).abs() < 1e-9);
        assert!(over_budget.extrapolated < 0.008);
        assert!((over_budget.min_32 - 0.008).abs() < 1e-9);
        assert!((over_budget.median_32 - 0.008).abs() < 1e-9);
    }

    #[test]
    fn verdict_math_rejects_when_extrapolated_cost_exceeds_budget() {
        let quadratic = vec![
            vec![0.001; 5],
            vec![0.004; 5],
            vec![0.016; 5],
            vec![0.064; 5],
        ];
        let (over, over_budget) =
            reach_probe_verdict_from_samples(&quadratic, PATTERN_SAFETY_DEFAULT_CAP, 1.0);
        assert!(over);
        assert!((over_budget.ratio - 4.0).abs() < 1e-9);
        assert!(over_budget.extrapolated > REACH_PROBE_BUDGET_SECONDS);
    }

    #[test]
    fn verdict_math_clamps_noisy_non_monotonic_ratios() {
        let non_monotonic = vec![
            vec![0.001; 5],
            vec![0.002; 5],
            vec![0.010; 5],
            vec![0.006; 5],
        ];
        let (over, over_budget) = reach_probe_verdict_from_samples(&non_monotonic, 512, 1.0);
        assert!((over_budget.ratio - 1.0).abs() < 1e-9);
        assert!(!over);
        assert!((over_budget.extrapolated - over_budget.min_32).abs() < 1e-12);
        assert!((over_budget.min_32 - 0.006).abs() < 1e-9);
    }

    #[test]
    fn verdict_math_treats_tiny_times_as_inconclusive() {
        let noisy = vec![vec![0.0; 5], vec![0.0; 5], vec![0.0; 5], vec![0.0002; 5]];
        let (over, over_budget) =
            reach_probe_verdict_from_samples(&noisy, PATTERN_SAFETY_DEFAULT_CAP, 1.0);
        assert!((over_budget.ratio - 1.0).abs() < 1e-9);
        assert!(!over);
    }

    #[test]
    fn verdict_divides_measurements_by_the_load_factor() {
        let samples = vec![vec![0.008; 5], vec![0.016; 5]];
        let (over_reference, _) =
            reach_probe_verdict_from_samples(&samples, PATTERN_SAFETY_DEFAULT_CAP, 1.0);
        let (over_loaded, loaded) =
            reach_probe_verdict_from_samples(&samples, PATTERN_SAFETY_DEFAULT_CAP, 4.0);
        assert!(over_reference);
        assert!(!over_loaded);
        assert!((loaded.min_32 * 4.0 - 0.016).abs() < 1e-9);
        // doublings = log2(262144 / 32000) = 3.032, so the extrapolation
        // multiplies by 8.192, not by 8.
        assert!((loaded.extrapolated * 4.0 - 0.131072).abs() < 1e-4);
    }

    #[test]
    fn cost_reason_reports_every_field() {
        let reason = reach_probe_cost_reason(
            None,
            &OverBudget {
                cap: 262144,
                extrapolated: 0.2,
                ratio: 2.0,
                min_32: 0.025,
                median_32: 0.026,
                load_factor: 2.5,
            },
        );
        assert!(reason.contains("at cap (262144 chars) is 0.200s"));
        assert!(reason.contains("0.05s safety budget"));
        assert!(reason.contains("growth ratio 2.00x"));
        assert!(reason.contains("min 0.0250s"));
        assert!(reason.contains("median 0.0260s"));
        assert!(reason.contains("over 5 runs"));
        assert!(reason.contains("normalized by host load factor 2.50"));
    }

    #[test]
    fn cost_reason_echoes_a_structural_violation() {
        assert_eq!(
            reach_probe_cost_reason(
                Some("nested quantifier"),
                &OverBudget {
                    cap: 262144,
                    extrapolated: 0.2,
                    ratio: 2.0,
                    min_32: 0.02,
                    median_32: 0.02,
                    load_factor: 1.0,
                },
            ),
            "nested quantifier"
        );
    }

    #[test]
    fn unreachable_reason_echoes_the_structural_violation() {
        assert_eq!(
            reach_probe_unreachable_reason(Some("some structural reason")),
            "some structural reason"
        );
        assert!(
            reach_probe_unreachable_reason(None)
                .starts_with("Pattern validation probe could not construct")
        );
    }

    #[test]
    fn timing_strategy_selects_ascending_for_flagged_patterns() {
        assert!(matches!(
            timing_strategy(Some("ambiguous optional tail"), false),
            TimingStrategy::Ascending
        ));
        assert!(matches!(
            timing_strategy(None, true),
            TimingStrategy::Ascending
        ));
        assert!(matches!(
            timing_strategy(None, false),
            TimingStrategy::Combined
        ));
        // Sizes widen for flagged patterns.
        assert_eq!(
            reach_probe_sizes_for_strategy(Some("x"), false),
            REACH_PROBE_SIZES.to_vec()
        );
        assert_eq!(
            reach_probe_sizes_for_strategy(None, false),
            vec![16000, 32000]
        );
    }

    #[test]
    fn timing_children_return_sorted_samples_per_probe() {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let result = time_reach_probes_subprocess(
            "abc",
            vec!["abc".to_owned(), "abcabc".to_owned()],
            deadline,
            Flags::default(),
        );
        let timing = result.expect("timing");
        assert_eq!(timing.samples_by_size.len(), 2);
        for samples in &timing.samples_by_size {
            assert!((1..=REACH_PROBE_SAMPLE_COUNT).contains(&samples.len()));
            let mut sorted = samples.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
            assert_eq!(samples, &sorted);
        }
        assert!((LOAD_FACTOR_FLOOR..=LOAD_FACTOR_CEILING).contains(&timing.load_factor));
    }

    #[test]
    fn single_probe_timing_returns_one_row() {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let timing = time_single_reach_probe_subprocess(
            "abc",
            "abcabc".to_owned(),
            deadline,
            Flags::default(),
        )
        .expect("timing");
        assert_eq!(timing.samples_by_size.len(), 1);
    }

    #[test]
    fn ascending_timing_walks_each_probe_individually() {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let timing = time_reach_probes_ascending(
            "abc",
            vec!["abc".to_owned(), "abcabc".to_owned()],
            deadline,
            Flags::default(),
        )
        .expect("timing");
        assert_eq!(timing.samples_by_size.len(), 2);
    }

    #[test]
    fn timing_returns_none_when_the_budget_is_exhausted() {
        let deadline = Instant::now() - std::time::Duration::from_secs(1);
        assert_eq!(
            time_reach_probes_subprocess("abc", vec!["a".to_owned()], deadline, Flags::default()),
            None
        );
        assert_eq!(
            time_single_reach_probe_subprocess("abc", "a".to_owned(), deadline, Flags::default()),
            None
        );
    }

    #[test]
    fn timing_children_return_none_on_compile_errors() {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        assert_eq!(
            time_reach_probes_subprocess(
                "[invalid",
                vec!["a".to_owned()],
                deadline,
                Flags::default()
            ),
            None
        );
    }

    #[test]
    fn ascending_timing_returns_none_when_the_budget_is_exhausted() {
        let deadline = Instant::now() - std::time::Duration::from_secs(1);
        assert_eq!(
            time_reach_probes_ascending("abc", vec!["a".to_owned()], deadline, Flags::default()),
            None
        );
    }

    #[test]
    fn test_strings_probe_certifies_safe_patterns() {
        let outcome = run_pattern_safety_probe(
            "abc",
            vec!["abc".to_owned(), "x".to_owned()],
            Flags::default(),
        );
        assert_eq!(outcome, TestStringsOutcome::Safe);
    }

    #[test]
    fn test_strings_probe_reports_compile_failures() {
        let outcome = run_pattern_safety_probe("[invalid", vec!["a".to_owned()], Flags::default());
        assert!(matches!(outcome, TestStringsOutcome::CompileFailed(_)));
    }

    #[test]
    fn stride_sampling_bounds_timed_probe_sets() {
        let probe_sets: Vec<Vec<String>> = (0..1200)
            .map(|index| vec![format!("p{index}"), format!("p{index}!")])
            .collect();
        let sampled = stride_sampled_probe_sets(probe_sets.clone(), 512);
        let expected: Vec<Vec<String>> = probe_sets.iter().step_by(3).cloned().collect();
        assert_eq!(sampled, expected);
        assert_eq!(
            stride_sampled_probe_sets(probe_sets[..512].to_vec(), 512).len(),
            512
        );
        assert_eq!(
            stride_sampled_probe_sets(probe_sets[..513].to_vec(), 512).len(),
            257
        );
    }

    #[test]
    fn unique_probe_sets_dedupe_by_digest() {
        let builders: Vec<super::super::probe_fill::ProbeBuilder> = vec![
            Box::new(|size: usize| "a".repeat(size)),
            Box::new(|size: usize| "a".repeat(size)),
            Box::new(|size: usize| "b".repeat(size)),
        ];
        let sets = unique_probe_sets(&builders, &[4, 8]);
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0], vec!["aaaa".to_owned(), "aaaaaaaa".to_owned()]);
        assert_eq!(sets[1], vec!["bbbb".to_owned(), "bbbbbbbb".to_owned()]);
    }

    #[test]
    fn cost_verdict_accepts_when_no_candidate_units_exist() {
        let outcome = reach_probe_cost_verdict(r"[a-z]", None, Flags::default());
        assert_eq!(outcome, CostOutcome::Safe);
    }

    #[test]
    fn cost_verdict_reports_unreachable_probes() {
        let outcome = reach_probe_cost_verdict(r"[^\x00-\U0010FFFF]+", None, Flags::default());
        assert_eq!(outcome, CostOutcome::Unreachable);
    }

    #[test]
    fn cost_verdict_echoes_structural_violations_when_builders_time_out() {
        // "a?" synthesizes but has no budget... use a builder-deadline
        // pattern: an unquantified optional tail has builders that never
        // trigger, so this stays safe.
        let outcome = reach_probe_cost_verdict("abc", None, Flags::default());
        assert_eq!(outcome, CostOutcome::Safe);
    }

    #[test]
    fn combined_timeout_is_the_budget_ladder_product() {
        assert!((reach_probe_combined_timeout_seconds() - 40.0).abs() < 1e-9);
        assert!((REACH_PROBE_CHILD_TIMEOUT_SECONDS - 2.5).abs() < 1e-9);
    }

    /// Extract the over-budget payload; panics on any other outcome.
    fn expect_over(outcome: CostOutcome) -> OverBudget {
        match outcome {
            CostOutcome::Over(over) => over,
            other => panic!("expected an over-budget verdict, got {other:?}"),
        }
    }

    fn failing_runner(
        _request: &ChildRequest,
        _timeout: f64,
    ) -> Result<ChildOutcome, ChildSpawnError> {
        Err(ChildSpawnError::Failed("stub".to_owned()))
    }

    fn reference_runner(
        reference: f64,
    ) -> impl Fn(&ChildRequest, f64) -> Result<ChildOutcome, ChildSpawnError> {
        move |_request, _timeout| Ok(ChildOutcome::Reference { reference })
    }

    #[test]
    fn reference_scan_falls_back_when_the_child_fails() {
        assert_eq!(
            measured_reference_scan(&failing_runner),
            REFERENCE_SCAN_FALLBACK_SECONDS
        );
    }

    #[test]
    fn reference_scan_falls_back_on_a_nonpositive_reference() {
        assert_eq!(
            measured_reference_scan(&reference_runner(0.0)),
            REFERENCE_SCAN_FALLBACK_SECONDS
        );
    }

    #[test]
    fn host_load_fails_open_to_one_when_the_child_fails() {
        assert_eq!(measured_host_load_factor(&failing_runner), 1.0);
    }

    #[test]
    fn host_load_normalizes_the_measured_reference() {
        // reference_scan_seconds() equals the measured constant on the
        // reference host, so a doubled measurement reads as load 2.0.
        let doubled = reference_scan_seconds() * 2.0;
        assert!((measured_host_load_factor(&reference_runner(doubled)) - 2.0).abs() < 1e-6);
    }

    fn stub_probes(
        value: f64,
    ) -> impl Fn(&str, Vec<String>, Instant, Flags) -> Option<ReachProbeTiming> {
        move |_pattern, probes, _deadline, _flags| {
            Some(ReachProbeTiming {
                samples_by_size: probes.iter().map(|_| vec![value; 5]).collect(),
                load_factor: 1.0,
            })
        }
    }

    fn stub_builders(count: usize) -> Vec<super::super::probe_fill::ProbeBuilder> {
        (0..count)
            .map(|index| {
                Box::new(move |size: usize| {
                    let fill = "a".repeat(size.saturating_sub(1));
                    format!(
                        "{}{fill}",
                        char::from_u32(0x4E00 + index as u32).unwrap_or('x')
                    )
                }) as super::super::probe_fill::ProbeBuilder
            })
            .collect()
    }

    #[test]
    fn builder_timeout_is_echoed_as_a_builder_deadline() {
        let outcome = reach_probe_cost_verdict_with_deadline(
            "a+",
            None,
            Flags::default(),
            Instant::now() - std::time::Duration::from_secs(1),
            &stub_probes(1e-9),
        );
        assert!(
            matches!(outcome, CostOutcome::BuilderDeadline(_)),
            "expected a builder deadline, got {outcome:?}"
        );
    }

    #[test]
    fn an_expired_deadline_after_builders_is_reported() {
        // The empty pattern synthesizes a trivially reaching probe and its
        // builder walk has nothing to walk, so synthesis completes without
        // polling the deadline; the expired deadline is then caught right
        // after the builders return.
        let outcome = reach_probe_cost_verdict_with_deadline(
            "",
            None,
            Flags::default(),
            Instant::now() - std::time::Duration::from_secs(1),
            &stub_probes(1e-9),
        );
        assert_eq!(
            outcome,
            CostOutcome::BuilderDeadline(
                "Pattern validation probe construction exceeded its deadline".into()
            )
        );
    }

    #[test]
    fn the_cost_verdict_returns_over_from_the_injected_timer() {
        let outcome = reach_probe_cost_verdict_with_deadline(
            "a+",
            None,
            Flags::default(),
            Instant::now() + std::time::Duration::from_secs(30),
            &stub_probes(0.1),
        );
        let over = expect_over(outcome);
        assert!((over.min_32 - 0.1).abs() < 1e-9);
        assert!((over.extrapolated - 0.1).abs() < 1e-9);
    }

    #[test]
    fn batched_mode_walks_every_set_when_under_budget() {
        let outcome = first_over_budget_reason_with(
            "a+",
            &stub_builders(REACH_PROBE_BATCH_SIZE + 1),
            262_144,
            None,
            Instant::now() + std::time::Duration::from_secs(30),
            Flags::default(),
            false,
            &stub_probes(1e-9),
        );
        assert_eq!(outcome, None);
    }

    #[test]
    fn batched_mode_stops_at_the_first_over_budget_set() {
        let outcome = first_over_budget_reason_with(
            "a+",
            &stub_builders(REACH_PROBE_BATCH_SIZE + 1),
            262_144,
            None,
            Instant::now() + std::time::Duration::from_secs(30),
            Flags::default(),
            false,
            &stub_probes(0.1),
        );
        assert!(matches!(outcome, Some(CostOutcome::Over(_))));
    }

    #[test]
    fn batched_mode_reports_a_deadline_when_the_child_fails() {
        let outcome = first_over_budget_reason_with(
            "a+",
            &stub_builders(REACH_PROBE_BATCH_SIZE + 1),
            262_144,
            None,
            Instant::now() + std::time::Duration::from_secs(30),
            Flags::default(),
            false,
            &|_pattern, _probes, _deadline, _flags| None,
        );
        assert_eq!(
            outcome,
            Some(CostOutcome::BuilderDeadline(
                "Pattern validation probe exceeded the killable-subprocess \
                 timeout while measuring reach-probe cost at scale"
                    .into()
            ))
        );
    }

    #[test]
    fn ascending_mode_reports_structural_when_the_child_fails() {
        // "(?:a+)+b" carries a nested-unbounded structural violation, so
        // the walk takes the ascending strategy and, on child failure,
        // the structural verdict stands.
        let outcome = reach_probe_cost_verdict_with_deadline(
            "(?:a+)+b",
            None,
            Flags::default(),
            Instant::now() + std::time::Duration::from_secs(30),
            &|_pattern, _probes, _deadline, _flags| None,
        );
        assert_eq!(outcome, CostOutcome::Structural);
    }

    #[test]
    fn verdict_for_set_retries_once_and_can_flip_to_safe() {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let probes = vec!["p".to_owned(); 2];
        let rows = vec![vec![0.1; 5]; 2];
        // First measurement over budget, retry under: the verdict flips.
        let calls = std::cell::Cell::new(0usize);
        let outcome = verdict_for_set(&probes, &rows, 1.0, 262_144, deadline, &|_retry: Vec<
            String,
        >| {
            calls.set(calls.get() + 1);
            Some(ReachProbeTiming {
                samples_by_size: vec![vec![1e-9; 5]; 2],
                load_factor: 1.0,
            })
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(outcome, None);
        // Retry still over: the verdict stands with the retry payload.
        let outcome = verdict_for_set(&probes, &rows, 1.0, 262_144, deadline, &|_retry: Vec<
            String,
        >| {
            Some(ReachProbeTiming {
                samples_by_size: vec![vec![0.2; 5]; 2],
                load_factor: 2.0,
            })
        });
        let over = expect_over(outcome.expect("an outcome"));
        assert!((over.min_32 - 0.1).abs() < 1e-9, "retry payload wins");
        assert!((over.load_factor - 2.0).abs() < 1e-9);
    }

    #[test]
    fn safety_probe_maps_every_child_outcome() {
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Err(ChildSpawnError::Timeout)
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::SubprocessTimeout
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Err(ChildSpawnError::Failed("spawn".to_owned()))
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::SpawnFailed("spawn".to_owned())
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Failed("bad pattern".to_owned()))
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::CompileFailed("bad pattern".to_owned())
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Safety {
                    safe: true,
                    reason: "Pattern appears safe".to_owned(),
                })
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::Safe
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Safety {
                    safe: false,
                    reason: "Pattern timed out on test string of length 42".to_owned(),
                })
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::SlowString(42)
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Safety {
                    safe: false,
                    reason: "Pattern validation failed: nope".to_owned(),
                })
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::CompileFailed("Pattern validation failed: nope".to_owned())
        );
        let runner =
            |_request: &ChildRequest, _timeout: f64| -> Result<ChildOutcome, ChildSpawnError> {
                Ok(ChildOutcome::Reference { reference: 0.5 })
            };
        assert_eq!(
            run_pattern_safety_probe_with("a", vec![], Flags::default(), &runner),
            TestStringsOutcome::SpawnFailed("unexpected child outcome".to_owned())
        );
    }

    #[test]
    #[should_panic(expected = "expected an over-budget verdict")]
    fn expect_over_rejects_other_outcomes() {
        let _ = expect_over(CostOutcome::Safe);
    }
}
