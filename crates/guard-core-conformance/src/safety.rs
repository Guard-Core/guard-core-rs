//! The `pattern_safety` corpus consumer: replays the vendored
//! `safety_gates.json` suite against the engine's
//! `validate_pattern_safety` and pins (`safe`, `reason_class`) per case.
//!
//! The corpus pins stable verdict tokens only; the numeric parts of
//! over-budget reasons are host-measured and never compared (the
//! `index.json` comparison contract).

use std::fs;

use guard_core_engine::redos::safety::{SafetyMode, validate_pattern_safety};
use serde_json::Value;

use crate::corpus::corpus_dir;
use crate::report::{CaseResult, Status};

/// One decoded `safety_gates` case.
#[derive(Debug, Clone)]
pub struct SafetyCase {
    pub id: String,
    pub pattern: String,
    pub mode: SafetyMode,
    pub expected_safe: bool,
    pub expected_reason_class: String,
}

fn mode_from_value(input: &Value) -> Result<SafetyMode, String> {
    let mode = input
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing input.mode".to_owned())?;
    match mode {
        "test_strings" => {
            let strings: Vec<String> = input
                .get("test_strings")
                .and_then(Value::as_array)
                .ok_or_else(|| "test_strings mode without a test_strings array".to_owned())?
                .iter()
                .map(|v| v.as_str().unwrap_or_default().to_owned())
                .collect();
            Ok(SafetyMode::TestStrings(strings))
        }
        "cost_verdict" => {
            let cap = input
                .get("max_content_length")
                .and_then(Value::as_u64)
                .map(|v| usize::try_from(v).map_err(|e| e.to_string()))
                .transpose()?;
            Ok(SafetyMode::CostVerdict {
                max_content_length: cap,
            })
        }
        other => Err(format!("unknown input.mode {other:?}")),
    }
}

fn decode_case(case: &Value) -> Result<SafetyCase, String> {
    let id = case
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing case id".to_owned())?
        .to_owned();
    let input = case
        .get("input")
        .ok_or_else(|| format!("{id}: missing input"))?;
    let pattern = input
        .get("pattern")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{id}: missing input.pattern"))?
        .to_owned();
    let mode = mode_from_value(input).map_err(|e| format!("{id}: {e}"))?;
    let expected = case
        .get("expected")
        .ok_or_else(|| format!("{id}: missing expected"))?;
    let expected_safe = expected
        .get("safe")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{id}: missing expected.safe"))?;
    let expected_reason_class = expected
        .get("reason_class")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{id}: missing expected.reason_class"))?
        .to_owned();
    Ok(SafetyCase {
        id,
        pattern,
        mode,
        expected_safe,
        expected_reason_class,
    })
}

/// Load the vendored `safety_gates` suite (all cases decoded or an error
/// naming the case).
///
/// # Errors
///
/// A missing or malformed suite file.
pub fn load_safety_cases() -> Result<Vec<SafetyCase>, String> {
    let path = corpus_dir().join("safety_gates.json");
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let suite: Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let cases = suite
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{}: no cases array", path.display()))?;
    cases.iter().map(decode_case).collect()
}

/// Replay one case: the engine verdict's (`safe`, `reason_class`) must match
/// the corpus pin exactly.
#[must_use]
pub fn run_safety_case(case: &SafetyCase) -> CaseResult {
    let key = format!("safety_gates::{}", case.id);
    let verdict = validate_pattern_safety(&case.pattern, &case.mode);
    let mut diffs = Vec::new();
    if verdict.safe != case.expected_safe {
        diffs.push(format!(
            "safe: expected {}, got {}",
            case.expected_safe, verdict.safe
        ));
    }
    let got_class = verdict.reason_class();
    if got_class != case.expected_reason_class {
        diffs.push(format!(
            "reason_class: expected {}, got {got_class}",
            case.expected_reason_class
        ));
    }
    let status = if diffs.is_empty() {
        Status::Passed
    } else {
        Status::Failed
    };
    CaseResult {
        case: key,
        suite: "safety_gates".to_owned(),
        status,
        diffs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_case_rejects_malformed_suite_entries() {
        let missing_id = serde_json::json!({ "input": {}, "expected": {} });
        assert_eq!(
            decode_case(&missing_id).expect_err("missing id"),
            "missing case id"
        );
        let missing_input = serde_json::json!({ "id": "c", "expected": {} });
        assert_eq!(
            decode_case(&missing_input).expect_err("missing input"),
            "c: missing input"
        );
        let missing_pattern = serde_json::json!({ "id": "c", "input": {}, "expected": {} });
        assert_eq!(
            decode_case(&missing_pattern).expect_err("missing pattern"),
            "c: missing input.pattern"
        );
        let bad_mode = serde_json::json!({
            "id": "c",
            "input": { "pattern": "a", "mode": "nope" },
            "expected": {},
        });
        assert_eq!(
            decode_case(&bad_mode).expect_err("bad mode"),
            "c: unknown input.mode \"nope\""
        );
        let missing_expected = serde_json::json!({
            "id": "c",
            "input": {
                "pattern": "a",
                "mode": "test_strings",
                "test_strings": ["a"],
            },
        });
        assert_eq!(
            decode_case(&missing_expected).expect_err("missing expected"),
            "c: missing expected"
        );
        let missing_safe = serde_json::json!({
            "id": "c",
            "input": {
                "pattern": "a",
                "mode": "test_strings",
                "test_strings": ["a"],
            },
            "expected": { "reason_class": "safe" },
        });
        assert_eq!(
            decode_case(&missing_safe).expect_err("missing expected.safe"),
            "c: missing expected.safe"
        );
        let missing_class = serde_json::json!({
            "id": "c",
            "input": {
                "pattern": "a",
                "mode": "test_strings",
                "test_strings": ["a"],
            },
            "expected": { "safe": true },
        });
        assert_eq!(
            decode_case(&missing_class).expect_err("missing expected.reason_class"),
            "c: missing expected.reason_class"
        );
    }

    #[test]
    fn run_safety_case_reports_expectation_drift() {
        let drifting = SafetyCase {
            id: "drift".to_owned(),
            pattern: "abc".to_owned(),
            mode: SafetyMode::TestStrings(vec![]),
            expected_safe: false,
            expected_reason_class: "compile_failed".to_owned(),
        };
        let result = run_safety_case(&drifting);
        assert_eq!(result.status, Status::Failed);
        assert_eq!(result.diffs.len(), 2);
        let agreeing = SafetyCase {
            expected_safe: true,
            expected_reason_class: "safe".to_owned(),
            ..drifting
        };
        let result = run_safety_case(&agreeing);
        assert_eq!(result.status, Status::Passed);
        assert!(result.diffs.is_empty());
    }

    #[test]
    fn mode_decoding_rejects_unknown_and_missing_modes() {
        let error =
            mode_from_value(&serde_json::json!({ "mode": "teleport" })).expect_err("unknown mode");
        assert_eq!(error, "unknown input.mode \"teleport\"");
        let error = mode_from_value(&serde_json::json!({})).expect_err("missing mode");
        assert_eq!(error, "missing input.mode");
    }
}
