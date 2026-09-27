use std::collections::HashSet;

use guard_core_conformance::baseline::{self, BASELINE_FILE};
use guard_core_conformance::corpus::{self, EXPECTED_SPEC_VERSION};
use guard_core_conformance::knobs::map_knobs;
use guard_core_conformance::pipeline::{self, PipelineCase};

fn first_diff(diffs: &[String], reason: &str) -> String {
    let diff = diffs.first().map_or("", String::as_str);
    if reason.is_empty() {
        diff.to_owned()
    } else {
        format!("{diff} [{reason}]")
    }
}

#[test]
fn pipeline_conformance_gate_against_spec_4_1_0() {
    let corpus = corpus::load_corpus().unwrap_or_else(|e| panic!("corpus load failed: {e}"));
    let knobs = map_knobs(&corpus.index.config_knobs)
        .unwrap_or_else(|e| panic!("knob mapping failed: {e}"));
    let suites = pipeline::load_pipeline_suites(&corpus.index)
        .unwrap_or_else(|e| panic!("pipeline suite load failed: {e}"));
    assert!(
        !suites.is_empty(),
        "the index lists no pipeline suites; corpus changed?"
    );
    let baseline = baseline::load_baseline()
        .unwrap_or_else(|e| panic!("baseline load failed ({BASELINE_FILE}): {e}"));
    assert_eq!(
        baseline.spec_version, EXPECTED_SPEC_VERSION,
        "baseline spec pin must match the runner requirement"
    );
    let baselined: HashSet<String> = baseline::baseline_keys(&baseline);

    let mut total = 0_usize;
    let mut failed = Vec::new();
    let mut xfailed = Vec::new();
    let mut stale = Vec::new();

    for (suite_name, cases) in &suites {
        for case in cases {
            total += 1;
            let key = format!("{suite_name}::{}", case.id);
            let result = pipeline::compare_case(case, &knobs);
            match result {
                Ok(diffs) if diffs.is_empty() => {
                    if baselined.contains(&key) {
                        stale.push(key);
                    }
                }
                Ok(diffs) => {
                    if baselined.contains(&key) {
                        xfailed.push((key, diffs));
                    } else {
                        failed.push((key, diffs));
                    }
                }
                Err(config_error) => {
                    // Fail closed: the reference SecurityConfig accepts
                    // every corpus configuration, so a construction failure
                    // is a port-side regression, never a tolerated xfail.
                    failed.push((key, vec![format!("DIVERGENCE config: {config_error}")]));
                }
            }
        }
    }

    for (key, diffs) in &failed {
        println!("FAIL {key}: {}", diffs.join("; "));
    }
    for (key, diffs) in &xfailed {
        let reason = baseline::baseline_reason(&baseline, key).unwrap_or("");
        println!("xfail {key} :: {}", first_diff(diffs, reason));
    }
    for key in &stale {
        println!("stale xfail baseline entry {key}: case now passes; remove the entry");
    }

    assert!(
        stale.is_empty(),
        "stale xfail baseline:\n{}",
        stale.join("\n")
    );
    if failed.is_empty() {
        println!(
            "pipeline conformance gate: {} passed, 0 failed, {} xfail, 0 config divergences (spec {EXPECTED_SPEC_VERSION})",
            total - xfailed.len(),
            xfailed.len()
        );
    } else {
        let listed: Vec<String> = failed.iter().map(|(key, _)| key.clone()).collect();
        panic!(
            "pipeline conformance drift: {} unbaselined failures / {total} cases\nadd them to {BASELINE_FILE} with an honest reason, or fix the drift:\n{}",
            failed.len(),
            listed.join("\n")
        );
    }
}

/// Unused today but keeps the `PipelineCase` import honest for the
/// structure checks below.
#[test]
fn every_pipeline_case_has_one_expected_record_per_drive() {
    let corpus = corpus::load_corpus().unwrap_or_else(|e| panic!("corpus load failed: {e}"));
    let suites = pipeline::load_pipeline_suites(&corpus.index)
        .unwrap_or_else(|e| panic!("pipeline suite load failed: {e}"));
    for (suite_name, cases) in &suites {
        for PipelineCase {
            id,
            drives,
            expected,
            ..
        } in cases
        {
            assert_eq!(
                drives.len(),
                expected.len(),
                "{suite_name}::{id}: {} drives but {} expected records",
                drives.len(),
                expected.len()
            );
        }
    }
}
