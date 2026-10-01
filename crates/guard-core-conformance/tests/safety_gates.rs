//! The `safety_gates` corpus consumer: every `pattern_safety` case is run
//! through the engine's full pattern-safety chain and the verdict must
//! match the oracle's pinned `safe` flag and `reason_class`.
//!
//! The numeric text inside a reason is host-dependent and never pinned;
//! the reason class token is.
//!
//! Divergences that are structural to the engine (the Rust engine executes
//! the linear-time `regex` crate where the reference's `re` backtracks)
//! must be listed in `DOCUMENTED_DIVERGENCES` with the reference source
//! that explains them; any other mismatch fails the gate.

use std::fs;
use std::path::PathBuf;

use guard_core_engine::redos::SafetyMode;
use serde_json::Value;

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/guard-core-spec-4.1.0/cases/safety_gates.json")
}

fn load_corpus() -> Value {
    let path = corpus_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("safety_gates.json parses")
}

/// Engine-inherent divergences, each tied to the reference source that
/// explains the difference. Anything not listed here that mismatches fails
/// the gate loudly.
///
/// All six are cost-verdict cases the reference rejects because Python's
/// `re` backtracks catastrophically on them (`_REACH_PROBE_TIMING_CHILD_SCRIPT`
/// in `guard-core/detection_engine/_redos_cost_arbiter.py` measures `re`).
/// The Rust engine executes the linear-time `regex` crate, so the same
/// probes cannot exceed the budget: the measured verdict is genuinely safe
/// for this engine. The deterministic layers agree with the oracle on
/// every one (each case's `test_strings` twin passes: the structural finding
/// is detected identically); only the empirical timing verdict diverges.
const DOCUMENTED_DIVERGENCES: &[(&str, &str)] = &[
    (
        "safety_cost_verdict_over_budget_01",
        "(\\d|\\w)*; is quadratic under Python re backtracking; the regex \
         crate executes it in linear time (reference _redos_cost_arbiter.py \
         child script times re.compile)",
    ),
    (
        "safety_cost_verdict_structural_nested_unbounded_01",
        "(a|aa)+$ backtracks quadratically under Python re; linear under the \
         regex crate (reference _redos_cost_arbiter.py child script)",
    ),
    (
        "safety_cost_verdict_structural_ambiguous_tail_01",
        "(?:\\w+\\s?)+$ backtracks quadratically under Python re; linear \
         under the regex crate (reference _redos_cost_arbiter.py child \
         script)",
    ),
    (
        "safety_cost_verdict_structural_literal_absorb_01",
        "[\\w-]*-- backtracks quadratically under Python re; linear under \
         the regex crate (reference _redos_cost_arbiter.py child script)",
    ),
    (
        "safety_cost_verdict_structural_literal_absorb_02",
        "[a-z]+abc backtracks quadratically under Python re; linear under \
         the regex crate (reference _redos_cost_arbiter.py child script)",
    ),
    (
        "safety_cost_verdict_structural_unreachable_terminator_01",
        "foo.*bar backtracks quadratically under Python re; linear under the \
         regex crate (reference _redos_cost_arbiter.py child script)",
    ),
];

fn mode_for(input: &Value) -> SafetyMode {
    match input["mode"].as_str() {
        Some("test_strings") => SafetyMode::TestStrings(
            input["test_strings"]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        ),
        _ => SafetyMode::CostVerdict {
            max_content_length: input["max_content_length"].as_u64().map(|v| v as usize),
        },
    }
}

#[test]
fn safety_gates_verdicts_match_the_oracle() {
    let corpus = load_corpus();
    assert_eq!(
        corpus["kind"].as_str(),
        Some("pattern_safety"),
        "unexpected corpus kind"
    );
    let cases = corpus["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "the corpus must not be empty");

    let mut passed = 0usize;
    let mut diverged = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let pattern = case["input"]["pattern"].as_str().expect("pattern");
        let mode = mode_for(&case["input"]);
        let verdict = guard_core_engine::redos::validate_pattern_safety(pattern, &mode);
        let want_safe = case["expected"]["safe"].as_bool().expect("safe flag");
        let want_class = case["expected"]["reason_class"]
            .as_str()
            .expect("reason class");
        let got_class = verdict.reason_class();
        if verdict.safe == want_safe && got_class == want_class {
            passed += 1;
            continue;
        }
        let note = DOCUMENTED_DIVERGENCES
            .iter()
            .find(|(divergent_id, _)| *divergent_id == id)
            .map(|(_, note)| *note);
        match note {
            Some(note) => {
                diverged += 1;
                println!(
                    "DOCUMENTED DIVERGENCE {id}: pattern {pattern:?} expected \
                     safe={want_safe} class={want_class}, got safe={} class={got_class} \
                     ({note})",
                    verdict.safe
                );
            }
            None => failures.push(format!(
                "{id}: pattern {pattern:?} expected safe={want_safe} \
                 class={want_class}, got safe={} class={got_class} reason={:?}",
                verdict.safe,
                verdict.reason.to_string()
            )),
        }
    }
    println!(
        "safety_gates: {} passed, {diverged} documented divergences, {} failed, {} total",
        passed,
        failures.len(),
        cases.len()
    );
    assert!(
        failures.is_empty(),
        "safety_gates mismatches ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        passed + diverged,
        cases.len(),
        "every case must resolve to a pass or a documented divergence"
    );
}
