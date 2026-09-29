pub mod baseline;
pub mod compare;
pub mod corpus;
pub mod detect;
pub mod knobs;
pub mod ledger;
pub mod pipeline;
pub mod report;

use serde_json::Value;

use crate::corpus::{Corpus, CorpusCase};
use crate::knobs::Knobs;
use crate::report::{CaseResult, Status};

#[must_use]
pub fn run_case(case: &CorpusCase, knobs: &Knobs) -> CaseResult {
    let verdict = detect::detect(&case.case.input.content, &case.case.input.context, knobs);
    let mut got = verdict.to_value();
    let mut want = case.case.expected.clone();

    compare::canonicalize(&mut got);
    compare::canonicalize(&mut want);

    let diffs = compare::compare_verdicts(&got, &want);
    let status = if diffs.is_empty() {
        Status::Passed
    } else {
        Status::Failed
    };

    CaseResult {
        case: case.key(),
        suite: case.suite.clone(),
        status,
        diffs,
    }
}

#[must_use]
pub fn run_corpus(corpus: &Corpus, knobs: &Knobs) -> Vec<CaseResult> {
    corpus::all_cases(corpus)
        .iter()
        .map(|case| run_case(case, knobs))
        .collect()
}

#[must_use]
pub fn corpus_patterns(corpus: &Corpus) -> Vec<PatternEvidence> {
    let mut by_pattern: std::collections::BTreeMap<String, PatternEvidence> =
        std::collections::BTreeMap::new();

    for case in corpus::all_cases(corpus) {
        let Some(threats) = case.case.expected.get("threats").and_then(Value::as_array) else {
            continue;
        };
        for threat in threats {
            let Some(pattern) = threat.get("pattern").and_then(Value::as_str) else {
                continue;
            };
            let evidence = by_pattern.entry(pattern.to_owned()).or_insert_with(|| {
                let category = threat
                    .get("category")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                PatternEvidence {
                    pattern: pattern.to_owned(),
                    category,
                    suites: Vec::new(),
                    cases: Vec::new(),
                }
            });
            if !evidence.suites.contains(&case.suite) {
                evidence.suites.push(case.suite.clone());
            }
            evidence.suites.sort();
            evidence.cases.push(MatchEvidence {
                case: case.key(),
                matched: threat
                    .get("match")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                position: threat
                    .get("position")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            });
        }
    }

    by_pattern.into_values().collect()
}

#[derive(Debug, Clone)]
pub struct PatternEvidence {
    pub pattern: String,
    pub category: String,
    pub suites: Vec<String>,
    pub cases: Vec<MatchEvidence>,
}

#[derive(Debug, Clone)]
pub struct MatchEvidence {
    pub case: String,
    pub matched: String,
    pub position: u64,
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use crate::corpus::{Case, CaseInput, LoadedSuite};
    use serde_json::json;

    fn corpus_case(id: &str, expected: Value) -> Corpus {
        Corpus {
            index: crate::corpus::IndexFile {
                spec_version: crate::corpus::EXPECTED_SPEC_VERSION.to_owned(),
                engine_version: "4.2.0".to_owned(),
                engine_commit: "deadbeef".to_owned(),
                fixed_ip: "10.0.0.1".to_owned(),
                config_knobs: json!({}),
                suites: std::collections::BTreeMap::new(),
                comparison: crate::corpus::Comparison {
                    threat_order: "position".to_owned(),
                    excluded_fields: Vec::new(),
                    float_precision: 6,
                },
            },
            suites: vec![LoadedSuite {
                name: "detect_sqli".to_owned(),
                cases: vec![Case {
                    id: id.to_owned(),
                    input: CaseInput {
                        content: "nothing bad".to_owned(),
                        context: "arg".to_owned(),
                    },
                    expected,
                }],
            }],
        }
    }

    fn knobs() -> Knobs {
        Knobs {
            max_content_length: 10_000,
            max_truncate_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            unmapped: Vec::new(),
        }
    }

    #[test]
    fn run_case_marks_diverging_expectations_failed() {
        let corpus = corpus_case("clean_case", serde_json::json!({"is_threat": true}));
        let results = run_corpus(&corpus, &knobs());
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].status, Status::Failed));
        assert!(!results[0].diffs.is_empty());
    }

    #[test]
    fn run_case_marks_matching_expectations_passed() {
        // the clean verdict matches its full expected record (`threats` is
        // the documented skip)
        let corpus = corpus_case(
            "clean_case",
            serde_json::json!({
                "is_threat": false,
                "threat_score": 0.0,
                "original_length": 11,
                "processed_length": 11,
                "detection_method": "enhanced",
            }),
        );
        let results = run_corpus(&corpus, &knobs());
        assert_eq!(
            results[0].status,
            Status::Passed,
            "diffs: {:?}",
            results[0].diffs
        );
        assert!(results[0].diffs.is_empty());
    }

    #[test]
    fn corpus_patterns_skips_cases_without_expected_threats() {
        let mut corpus = corpus_case(
            "clean_case",
            serde_json::json!({"is_threat": false, "threats": []}),
        );
        // a second case with no `threats` key at all: skipped entirely
        corpus.suites[0].cases.push(Case {
            id: "no_threats_key".to_owned(),
            input: CaseInput {
                content: "nothing".to_owned(),
                context: "arg".to_owned(),
            },
            expected: serde_json::json!({"is_threat": false}),
        });
        let evidence = corpus_patterns(&corpus);
        assert!(evidence.is_empty(), "no expected threats: {evidence:?}");
    }
}
