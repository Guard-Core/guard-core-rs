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

use super::child::{run_child_request, ChildOutcome, ChildRequest, ChildSpawnError};
use super::prefilters::first_structural_safety_violation;
use super::probe_batches::{
    decode_reach_timing, probe_set_digest, valid_timing_rows, ReachProbeTiming,
    REACH_PROBE_BATCH_SIZE,
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
    static MEASURED: LazyLock<f64> = LazyLock::new(|| {
        match run_child_request(
            &ChildRequest::ReferenceLoad,
            REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS,
        ) {
            Ok(ChildOutcome::Reference { reference }) if reference > 0.0 => reference,
            _ => REFERENCE_SCAN_FALLBACK_SECONDS,
        }
    });
    *MEASURED
}

/// Reference `_load_factor`.
#[must_use]
pub fn load_factor(reference_seconds: f64) -> f64 {
    (reference_seconds / reference_scan_seconds())
        .clamp(LOAD_FACTOR_FLOOR, LOAD_FACTOR_CEILING)
}

/// Host load factor measured in a killable child; fails open to 1.0.
#[must_use]
pub fn measure_host_load_factor() -> f64 {
    match run_child_request(
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
        let timing = time_single_reach_probe_subprocess(
            pattern,
            probe,
            deadline,
            flags,
        )?;
        samples_by_size.extend(timing.samples_by_size);
        load_factor_min = load_factor_min.min(timing.load_factor);
    }
    Some(ReachProbeTiming {
        samples_by_size,
        load_factor: load_factor_min,
    })
}

/// The timing strategy signature.
pub type TimeProbes<'a> = &'a dyn Fn(&str, Vec<String>, Instant, super::ast::Flags) -> Option<ReachProbeTiming>;

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
        TimingStrategy::Combined => {
            time_reach_probes_subprocess(pattern, probes, deadline, flags)
        }
        TimingStrategy::Ascending => {
            time_reach_probes_ascending(pattern, probes, deadline, flags)
        }
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
    (extrapolated > REACH_PROBE_BUDGET_SECONDS, OverBudget {
        cap,
        extrapolated,
        ratio,
        min_32,
        median_32,
        load_factor: load,
    })
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
        let probes: Vec<String> =
            probe_sizes.iter().map(|size| builder(*size)).collect();
        let digest = probe_set_digest(&probes);
        if seen.contains(&digest) {
            continue;
        }
        seen.push(digest);
        sets.push(probes);
    }
    sets
}

fn stride_sampled_probe_sets(
    probe_sets: Vec<Vec<String>>,
    cap: usize,
) -> Vec<Vec<String>> {
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
    let cap = max_content_length
        .filter(|length| *length > 0)
        .unwrap_or(PATTERN_SAFETY_DEFAULT_CAP);
    let structural_violation = first_structural_safety_violation(pattern);
    let bounded_repeat_risk = has_large_bounded_repeat(pattern, flags);
    if synthesize_reaching_probe(pattern).is_none() {
        return CostOutcome::Unreachable;
    }
    let builders =
        match reach_probe_candidate_builders(pattern, flags, Some(deadline)) {
            Ok(builders) => builders,
            Err(BuilderTimeout(message)) => {
                return CostOutcome::BuilderDeadline(
                    structural_violation.unwrap_or(message),
                );
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
    if let Some(over) = first_over_budget_reason(
        pattern,
        &builders,
        cap,
        structural_violation.as_deref(),
        deadline,
        flags,
        bounded_repeat_risk,
    ) {
        return over;
    }
    CostOutcome::Safe
}

#[allow(clippy::too_many_arguments)]
fn first_over_budget_reason(
    pattern: &str,
    builders: &[super::probe_fill::ProbeBuilder],
    cap: usize,
    structural_violation: Option<&str>,
    deadline: Instant,
    flags: super::ast::Flags,
    bounded_repeat_risk: bool,
) -> Option<CostOutcome> {
    let strategy = timing_strategy(structural_violation, bounded_repeat_risk);
    let probe_sizes = reach_probe_sizes_for_strategy(
        structural_violation,
        bounded_repeat_risk,
    );
    let probe_sets = stride_sampled_probe_sets(
        unique_probe_sets(builders, &probe_sizes),
        MAX_TIMED_PROBE_SETS,
    );
    let time_probes = |probes: Vec<String>| {
        run_with_strategy(&strategy, pattern, probes, deadline, flags)
    };
    if structural_violation.is_none()
        && !bounded_repeat_risk
        && builders.len() >= REACH_PROBE_BATCH_SIZE
    {
        // Batched mode: one child per batch of probe sets, sliced back per
        // set; the first over-budget set stops the walk (the reference
        // streams batches lazily).
        for batch in probe_sets.chunks(REACH_PROBE_BATCH_SIZE) {
            let flattened: Vec<String> = batch.concat();
            let validated = valid_timing_rows(
                time_probes(flattened.clone()).as_ref(),
                flattened.len(),
            );
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
                    &time_probes,
                ) {
                    return Some(outcome);
                }
                offset = next_offset;
            }
        }
        return None;
    }
    for probes in probe_sets {
        let validated =
            valid_timing_rows(time_probes(probes.clone()).as_ref(), probes.len());
        let Some((rows, load)) = validated else {
            return batch_timeout_outcome(structural_violation);
        };
        if let Some(outcome) = verdict_for_set(
            &probes,
            &rows,
            load,
            cap,
            deadline,
            &time_probes,
        ) {
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
        let retry = valid_timing_rows(
            time_probes(probes.to_vec()).as_ref(),
            probes.len(),
        );
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
    let outcome = run_child_request(
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
        Ok(_) => TestStringsOutcome::SpawnFailed(
            "unexpected child outcome".to_owned(),
        ),
    }
}
