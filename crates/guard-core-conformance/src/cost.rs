//! Cost-budget conformance for the `cost_bodies` suite (`index.json`
//! `cost_budgets.method`). Verdict parity for large inputs is enforced by
//! the detect runner; this module enforces scan-cost ceilings so gross cost
//! divergence from the reference can never pass silently again.
//!
//! Ceilings are self-relative so they survive host variance: the run
//! measures its own best-of-N at the 8 KiB workload and every other
//! workload must satisfy
//!
//! ```text
//! best_ms <= K * best8_ms * (size_bytes / 8192) + floor_ms
//! ```
//!
//! with `K=5` and `floor_ms=250`, tolerating host speed and fixed overhead
//! while catching superlinear scans. Sampling is adaptive (3 runs at
//! <64 KiB, 2 at <256 KiB, 1 above) to keep the suite CI-viable.

use crate::corpus::corpus_dir;
use guard_core_engine::detect::{DetectConfig, detect};
use serde_json::Value;
use std::time::Instant;

fn config() -> DetectConfig {
    // The corpus config_knobs, mapped (see knobs.rs): the same values every
    // other conformance runner in this crate uses.
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

fn runs_for(size_bytes: usize) -> usize {
    if size_bytes >= 256 * 1024 {
        1
    } else if size_bytes >= 64 * 1024 {
        2
    } else {
        3
    }
}

#[test]
fn cost_bodies_stay_under_self_relative_ceilings() {
    let dir = corpus_dir();
    let index: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("index.json")).expect("index.json"))
            .expect("index.json parses");
    let cost = index
        .get("cost_budgets")
        .expect("index.json must carry cost_budgets; regenerate the corpus");
    let k = cost
        .get("k")
        .and_then(Value::as_f64)
        .expect("cost_budgets.k");
    let floor = cost
        .get("floor_ms")
        .and_then(Value::as_f64)
        .expect("cost_budgets.floor_ms");
    let budgets = cost
        .get("budgets")
        .and_then(Value::as_object)
        .expect("cost_budgets.budgets");

    let suite: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("cost_bodies.json")).expect("cost_bodies.json"),
    )
    .expect("cost_bodies.json parses");
    let cases = suite
        .get("cases")
        .and_then(Value::as_array)
        .expect("cost_bodies cases")
        .clone();
    assert!(
        !cases.is_empty(),
        "cost_bodies matched zero cases; a vacuous pass is a failure"
    );

    let cfg = config();
    let mut measured: Vec<(String, f64, bool, usize)> = Vec::new();
    for case in &cases {
        let id = case["id"].as_str().expect("case id").to_owned();
        let body = case["input"]["content"].as_str().expect("content");
        let context = case["input"]["context"].as_str().unwrap_or("request_body");
        let expected = case["expected"]["is_threat"].as_bool().expect("is_threat");
        let size = body.len();
        let mut best = f64::INFINITY;
        let mut threat = false;
        for _ in 0..runs_for(size) {
            let start = Instant::now();
            let verdict = detect(body, context, &cfg);
            threat = verdict.is_threat;
            best = best.min(start.elapsed().as_secs_f64() * 1000.0);
        }
        let drift = verdict_drift_line(&id, threat, expected);
        assert!(drift.is_none(), "cost_bodies verdict drift on {id}");
        measured.push((id, best, threat, size));
    }

    let best8 = measured
        .iter()
        .find(|(id, ..)| id == "cost_prose_8kib")
        .map(|(_, best, _, _)| *best)
        .expect("cost_prose_8kib anchors the ceilings");

    // ceiling_violations prints every under-ceiling line as it goes, so the
    // run log carries the measured-vs-ceiling table.
    let overs = ceiling_violations(best8, k, floor, &measured);
    assert!(
        overs.is_empty(),
        "cost ceilings exceeded (register + fix, or fix the engine): {overs:#?}"
    );
    // Recorded reference budget ids must match the suite, so a corpus edit
    // without a regen cannot pass silently.
    assert_eq!(
        budgets.len(),
        cases.len(),
        "cost_budgets entries must cover every cost_bodies case"
    );
}

/// The drift line for a verdict that disagrees with the corpus, if any.
fn verdict_drift_line(id: &str, threat: bool, expected: bool) -> Option<String> {
    if threat == expected {
        None
    } else {
        Some(format!("{id}: verdict {threat} != expected {expected}"))
    }
}

/// The self-relative ceiling check, pure so the violation branch is
/// unit-testable without a corpus run. The multiply-add lint is allowed on
/// purpose: the ceiling is a coarse pass/fail threshold where FMA precision
/// is irrelevant, and the formula is kept in textbook form for review.
#[allow(clippy::suboptimal_flops)]
fn ceiling_violations(
    best8_ms: f64,
    k: f64,
    floor_ms: f64,
    measured: &[(String, f64, bool, usize)],
) -> Vec<String> {
    let mut overs = Vec::new();
    for (id, best, _, size) in measured {
        let ceiling = (k * best8_ms * (*size as f64 / 8192.0)) + floor_ms;
        let line =
            format!("cost budgets/{id}: best={best:.1} ms ceiling={ceiling:.1} ms (size {size})");
        if *best > ceiling {
            overs.push(line);
        } else {
            println!("{line}");
        }
    }
    overs
}

#[test]
fn ceiling_violations_reports_superlinear_workloads() {
    let measured = vec![
        ("anchor".to_owned(), 10.0, false, 8192),
        ("linear".to_owned(), 70.0, false, 64 * 1024),
        ("superlinear".to_owned(), 5_000.0, false, 64 * 1024),
    ];
    let overs = ceiling_violations(10.0, 5.0, 250.0, &measured);
    assert_eq!(overs.len(), 1, "only the superlinear workload is reported");
    assert!(
        overs[0].contains("superlinear"),
        "report names the workload"
    );
    let linear = vec![
        ("anchor".to_owned(), 10.0, false, 8192),
        ("linear".to_owned(), 70.0, false, 64 * 1024),
    ];
    assert!(ceiling_violations(10.0, 5.0, 250.0, &linear).is_empty());
}

#[test]
fn verdict_drift_line_reports_disagreements() {
    assert!(verdict_drift_line("a", true, true).is_none());
    assert_eq!(
        verdict_drift_line("a", false, true).unwrap(),
        "a: verdict false != expected true"
    );
}
