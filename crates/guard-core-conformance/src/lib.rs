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
