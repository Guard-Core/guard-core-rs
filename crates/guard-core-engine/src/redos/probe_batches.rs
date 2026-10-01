//! Probe-set digests, timing validation, and batch measurement.
//!
//! Port of the reference `_redos_probe_batches.py`.

use sha2::{Digest, Sha256};

use super::child::ChildOutcome;

/// Reference `_REACH_PROBE_BATCH_SIZE`.
pub const REACH_PROBE_BATCH_SIZE: usize = 128;

/// One timed probe set with its validated rows and host load factor.
pub type TimedProbeSet = (Vec<String>, Option<Vec<Vec<f64>>>, f64);

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
    if timing.samples_by_size.len() != expected_rows || !valid_load_factor(timing.load_factor) {
        return None;
    }
    if !timing
        .samples_by_size
        .iter()
        .all(|row| valid_sample_row(row))
    {
        return None;
    }
    Some((timing.samples_by_size.clone(), timing.load_factor))
}

/// Decode a reach-timing child payload into validated rows plus the
/// reference scan (reference `_decode_reach_timing`).
pub fn decode_reach_timing(outcome: Option<&ChildOutcome>) -> Option<(Vec<Vec<f64>>, f64)> {
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
) -> Vec<TimedProbeSet> {
    let mut out: Vec<TimedProbeSet> = Vec::new();
    let mut batch: Vec<Vec<String>> = Vec::new();
    for probes in probe_sets.drain(..) {
        batch.push(probes);
        if batch.len() < REACH_PROBE_BATCH_SIZE {
            continue;
        }
        out.extend(measure_probe_batch(
            pattern,
            batch,
            deadline,
            flags,
            time_probes,
        ));
        batch = Vec::new();
    }
    if !batch.is_empty() {
        out.extend(measure_probe_batch(
            pattern,
            batch,
            deadline,
            flags,
            time_probes,
        ));
    }
    out
}

fn measure_probe_batch(
    pattern: &str,
    batch: Vec<Vec<String>>,
    deadline: std::time::Instant,
    flags: super::ast::Flags,
    time_probes: super::cost_arbiter::TimeProbes<'_>,
) -> Vec<TimedProbeSet> {
    let flattened: Vec<String> = batch.iter().flatten().cloned().collect();
    let timing = time_probes(pattern, flattened.clone(), deadline, flags);
    let valid = valid_timing_rows(timing.as_ref(), flattened.len());
    let Some((rows, load_factor)) = valid else {
        return batch
            .into_iter()
            .map(|probes| (probes, None, 1.0))
            .collect();
    };
    let mut out: Vec<TimedProbeSet> = Vec::new();
    let mut offset = 0usize;
    for probes in batch {
        let next_offset = offset + probes.len();
        out.push((
            probes,
            Some(rows[offset..next_offset].to_vec()),
            load_factor,
        ));
        offset = next_offset;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probes(pairs: &[&str]) -> Vec<String> {
        pairs.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn digest_preserves_probe_set_boundaries() {
        assert_ne!(
            probe_set_digest(&probes(&["a", "bc"])),
            probe_set_digest(&probes(&["ab", "c"]))
        );
        assert_eq!(
            probe_set_digest(&probes(&["a", "bc"])),
            probe_set_digest(&probes(&["a", "bc"]))
        );
    }

    #[test]
    fn valid_timing_rows_reject_shape_and_value_drift() {
        let timing = ReachProbeTiming {
            samples_by_size: vec![vec![0.1, 0.2]],
            load_factor: 1.0,
        };
        assert_eq!(
            valid_timing_rows(Some(&timing), 2),
            None,
            "row count must match"
        );
        let mut nan = timing.clone();
        nan.samples_by_size = vec![vec![f64::NAN]];
        assert_eq!(valid_timing_rows(Some(&nan), 1), None);
        let mut negative = timing.clone();
        negative.samples_by_size = vec![vec![-1.0]];
        assert_eq!(valid_timing_rows(Some(&negative), 1), None);
        let mut empty_row = timing.clone();
        empty_row.samples_by_size = vec![vec![]];
        assert_eq!(valid_timing_rows(Some(&empty_row), 1), None);
        let mut load = timing;
        load.load_factor = 0.0;
        assert_eq!(valid_timing_rows(Some(&load), 1), None);
        assert_eq!(valid_timing_rows(None, 1), None);
    }

    #[test]
    fn valid_timing_rows_accepts_clean_rows() {
        let timing = ReachProbeTiming {
            samples_by_size: vec![vec![0.1, 0.2], vec![0.3]],
            load_factor: 2.5,
        };
        let (rows, load) = valid_timing_rows(Some(&timing), 2).expect("valid");
        assert_eq!(rows.len(), 2);
        assert_eq!(load, 2.5);
    }

    #[test]
    fn decode_reach_timing_sorts_each_row() {
        let outcome = ChildOutcome::Timing {
            results: vec![vec![0.3, 0.1, 0.2]],
            reference: 0.002,
        };
        let (rows, reference) = decode_reach_timing(Some(&outcome)).expect("decoded");
        assert_eq!(rows, vec![vec![0.1, 0.2, 0.3]]);
        assert_eq!(reference, 0.002);
    }

    #[test]
    fn decode_reach_timing_rejects_other_outcomes_and_bad_rows() {
        assert_eq!(
            decode_reach_timing(Some(&ChildOutcome::Failed("x".into()))),
            None
        );
        assert_eq!(decode_reach_timing(None), None);
        let empty = ChildOutcome::Timing {
            results: vec![],
            reference: 0.1,
        };
        assert_eq!(decode_reach_timing(Some(&empty)), None);
        let bad_reference = ChildOutcome::Timing {
            results: vec![vec![0.1]],
            reference: -1.0,
        };
        assert_eq!(decode_reach_timing(Some(&bad_reference)), None);
        let not_finite = ChildOutcome::Timing {
            results: vec![vec![f64::INFINITY]],
            reference: 0.1,
        };
        assert_eq!(decode_reach_timing(Some(&not_finite)), None);
    }

    #[test]
    fn batched_timings_preserve_probe_order_and_all_rows() {
        let probe_sets: Vec<Vec<String>> = (0..(REACH_PROBE_BATCH_SIZE + 1))
            .map(|index| probes(&[&format!("p{index}")]))
            .collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let calls: std::sync::Mutex<Vec<Vec<String>>> = std::sync::Mutex::new(Vec::new());
        let time_probes = |pattern: &str,
                           batch: Vec<String>,
                           _deadline: std::time::Instant,
                           _flags: super::super::ast::Flags|
         -> Option<ReachProbeTiming> {
            assert_eq!(pattern, "test");
            calls.lock().expect("mutex").push(batch.clone());
            Some(ReachProbeTiming {
                samples_by_size: batch.iter().map(|_probe| vec![0.0]).collect(),
                load_factor: 1.0,
            })
        };
        let result = batched_reach_probe_timings(
            "test",
            probe_sets.clone(),
            deadline,
            super::super::ast::Flags::default(),
            &time_probes,
        );
        let calls = calls.into_inner().expect("mutex");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].len(), REACH_PROBE_BATCH_SIZE);
        assert_eq!(calls[1], probe_sets[REACH_PROBE_BATCH_SIZE]);
        let sets: Vec<Vec<String>> = result
            .iter()
            .map(|(probes, _rows, _load)| probes.clone())
            .collect();
        assert_eq!(sets, probe_sets);
        assert_eq!(result[0].1, Some(vec![vec![0.0]]));
        assert_eq!(
            result.last().expect("nonempty").1.clone().expect("rows"),
            vec![vec![0.0]]
        );
    }

    #[test]
    fn batched_timings_fail_closed_for_malformed_child_results() {
        let probe_sets = vec![probes(&["a", "b"])];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let time_probes = |_pattern: &str,
                           _batch: Vec<String>,
                           _deadline: std::time::Instant,
                           _flags: super::super::ast::Flags|
         -> Option<ReachProbeTiming> { None };
        let result = batched_reach_probe_timings(
            "test",
            probe_sets,
            deadline,
            super::super::ast::Flags::default(),
            &time_probes,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, None);
        assert_eq!(result[0].2, 1.0);
    }

    #[test]
    fn reach_probe_timing_holds_rows_and_load() {
        let timing = ReachProbeTiming {
            samples_by_size: vec![vec![1.0]],
            load_factor: 2.0,
        };
        let clone = timing.clone();
        assert_eq!(clone, timing);
    }
}
