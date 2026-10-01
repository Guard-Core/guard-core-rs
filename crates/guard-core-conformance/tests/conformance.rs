use std::collections::HashSet;

use guard_core_conformance::baseline::{self, BASELINE_FILE};
use guard_core_conformance::corpus::{self, EXPECTED_SPEC_VERSION};
use guard_core_conformance::knobs::map_knobs;
use guard_core_conformance::report::{evaluate, suite_table};
use guard_core_conformance::run_corpus;

#[test]
fn conformance_gate_against_spec_4_1_0() {
    let corpus = corpus::load_corpus().unwrap_or_else(|e| panic!("corpus load failed: {e}"));
    let knobs = map_knobs(&corpus.index.config_knobs)
        .unwrap_or_else(|e| panic!("knob mapping failed: {e}"));
    let baseline = baseline::load_baseline()
        .unwrap_or_else(|e| panic!("baseline load failed ({BASELINE_FILE}): {e}"));
    assert_eq!(
        baseline.spec_version, EXPECTED_SPEC_VERSION,
        "baseline spec pin must match the runner requirement"
    );

    let results = run_corpus(&corpus, &knobs);
    let baselined: HashSet<String> = baseline_keys(&baseline);

    match evaluate(&results, &baselined) {
        Ok(report) => {
            let suite_names: Vec<String> = corpus.index.suites.keys().cloned().collect();
            print!("{}", suite_table(&report, &suite_names));
            println!(
                "conformance gate: {} passed, {} failed, {} xfail, {} not_run (spec {})",
                report.passed.len(),
                report.failed.len(),
                report.xfail.len(),
                report.not_run.len(),
                EXPECTED_SPEC_VERSION
            );
            for r in &report.xfail {
                let reason = baseline::baseline_reason(&baseline, &r.case).unwrap_or("");
                println!("  xfail {} :: {}", r.case, first_diff(&r.diffs, reason));
            }
        }
        Err(drift) => panic!("{}", drift.describe()),
    }
}

fn baseline_keys(b: &baseline::Baseline) -> HashSet<String> {
    b.cases.iter().map(|c| c.case.clone()).collect()
}

fn first_diff(diffs: &[String], reason: &str) -> String {
    let diff = diffs.first().map_or("", String::as_str);
    if reason.is_empty() {
        diff.to_owned()
    } else {
        format!("{diff} [{reason}]")
    }
}

#[test]
fn safety_gates_gate_against_spec_4_1_0() {
    let cases = guard_core_conformance::safety::load_safety_cases()
        .unwrap_or_else(|e| panic!("safety_gates load failed: {e}"));
    assert!(
        cases.len() >= 90,
        "the vendored safety_gates suite must be the reference suite (got {} cases)",
        cases.len()
    );
    let baseline = baseline::load_baseline()
        .unwrap_or_else(|e| panic!("baseline load failed ({BASELINE_FILE}): {e}"));
    let baselined = baseline_keys(&baseline);

    let results: Vec<guard_core_conformance::report::CaseResult> = cases
        .iter()
        .map(guard_core_conformance::safety::run_safety_case)
        .collect();

    match evaluate(&results, &baselined) {
        Ok(report) => {
            println!(
                "safety_gates gate: {} passed, {} failed, {} xfail (of {} cases)",
                report.passed.len(),
                report.failed.len(),
                report.xfail.len(),
                results.len()
            );
            for r in &report.xfail {
                let reason = baseline::baseline_reason(&baseline, &r.case).unwrap_or("");
                println!("  xfail {} :: {}", r.case, first_diff(&r.diffs, reason));
            }
        }
        Err(drift) => panic!("{}", drift.describe()),
    }
}
