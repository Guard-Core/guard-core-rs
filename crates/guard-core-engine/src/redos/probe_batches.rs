//! Probe-set digests, timing validation, and batch measurement.
//!
//! Port of the reference `_redos_probe_batches.py`.

use sha2::{Digest, Sha256};

use super::child::ChildOutcome;

/// Reference `_REACH_PROBE_BATCH_SIZE`.
pub const REACH_PROBE_BATCH_SIZE: usize = 128;

/// A validated reach-probe timing (the reference `ReachProbeTiming`).
#[derive(Debug, Clone, PartialEq)]
pub struct ReachProbeTiming {
    /// Sorted samples per probe row.
    pub samples_by_size: Vec<Vec<f64>>,
    /// Host load factor the samples were measured under.
    pub load_factor: f64,
}

/// Reference `_probe_set_digest`.
#[must_use]
pub fn probe_set_digest(probes: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((probes.len() as u32).to_be_bytes());
    for probe in probes {
        let encoded = probe.as_bytes();
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    digest.finalize().into()
}

fn valid_sample(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn valid_sample_row(row: &[f64]) -> bool {
    !row.is_empty() && row.iter().all(|sample| valid_sample(*sample))
}

fn valid_load_factor(value: f64) -> bool {
    valid_sample(value) && value > 0.0
}

/// Reference `_valid_timing_rows`: validates the row count and every
/// sample, then splits rows and load factor.
pub fn valid_timing_rows(
    timing: Option<&ReachProbeTiming>,
    expected_rows: usize,
) -> Option<(Vec<Vec<f64>>, f64)> {
    let timing = timing?;
    if timing.samples_by_size.len() != expected_rows
        || !valid_load_factor(timing.load_factor)
    {
        return None;
    }
    if !timing.samples_by_size.iter().all(|row| valid_sample_row(row)) {
        return None;
    }
    Some((timing.samples_by_size.clone(), timing.load_factor))
}

/// Decode a reach-timing child payload into validated rows plus the
/// reference scan (reference `_decode_reach_timing`).
pub fn decode_reach_timing(
    outcome: Option<&ChildOutcome>,
) -> Option<(Vec<Vec<f64>>, f64)> {
    match outcome? {
        ChildOutcome::Timing { results, reference } => {
            if results.is_empty() || !results.iter().all(|row| valid_sample_row(row)) {
                return None;
            }
            if !valid_sample(*reference) {
                return None;
            }
            let rows = results
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    row
                })
                .collect();
            Some((rows, *reference))
        }
        _ => None,
    }
}

/// Reference `_batched_reach_probe_timings`.
pub fn batched_reach_probe_timings(
    pattern: &str,
    mut probe_sets: Vec<Vec<String>>,
    deadline: std::time::Instant,
    flags: super::ast::Flags,
    time_probes: super::cost_arbiter::TimeProbes<'_>,
) -> Vec<(Vec<String>, Option<Vec<Vec<f64>>>, f64)> {
    let mut out: Vec<(Vec<String>, Option<Vec<Vec<f64>>>, f64)> = Vec::new();
    let mut batch: Vec<Vec<String>> = Vec::new();
    for probes in probe_sets.drain(..) {
        batch.push(probes);
        if batch.len() < REACH_PROBE_BATCH_SIZE {
            continue;
        }
        out.extend(measure_probe_batch(pattern, batch, deadline, flags, time_probes));
        batch = Vec::new();
    }
    if !batch.is_empty() {
        out.extend(measure_probe_batch(pattern, batch, deadline, flags, time_probes));
    }
    out
}

fn measure_probe_batch(
    pattern: &str,
    batch: Vec<Vec<String>>,
    deadline: std::time::Instant,
    flags: super::ast::Flags,
    time_probes: super::cost_arbiter::TimeProbes<'_>,
) -> Vec<(Vec<String>, Option<Vec<Vec<f64>>>, f64)> {
    let flattened: Vec<String> = batch.iter().flatten().cloned().collect();
    let timing = time_probes(pattern, flattened.clone(), deadline, flags);
    let valid = valid_timing_rows(timing.as_ref(), flattened.len());
    let Some((rows, load_factor)) = valid else {
        return batch
            .into_iter()
            .map(|probes| (probes, None, 1.0))
            .collect();
    };
    let mut out: Vec<(Vec<String>, Option<Vec<Vec<f64>>>, f64)> = Vec::new();
    let mut offset = 0usize;
    for probes in batch {
        let next_offset = offset + probes.len();
        out.push((probes, Some(rows[offset..next_offset].to_vec()), load_factor));
        offset = next_offset;
    }
    out
}
