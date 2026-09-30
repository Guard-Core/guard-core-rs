//! The residual-pattern cross-check: every ledger residual (the lookaround
//! and backreference sources the `regex` crate rejects) is compiled under
//! `fancy-regex` and verified against the engine's structural matchers on
//! the corpus evidence - the same (match text, position) pairs the detect
//! gate records.
//!
//! The structural matchers remain the served path
//! (`served_by = "structural matcher"` in the ledger); fancy-regex is the
//! oracle that pins their semantics to the reference sources. A pattern
//! whose fancy-regex oracle disagrees with the engine on binary-noise
//! candidate selection carries the documented detection limit in its
//! ledger entry (`fancy_regex`); the rest carry `fancy_regex = "verified"`.

use std::collections::BTreeMap;

use fancy_regex::Regex as FancyRegex;
use guard_core_conformance::PatternEvidence;
use guard_core_conformance::corpus::{self, Corpus};
use guard_core_conformance::detect;
use guard_core_conformance::knobs::map_knobs;
use guard_core_conformance::ledger::{self, ResidualEntry};
use serde_json::Value;

fn load() -> (Corpus, ledger::Ledger, BTreeMap<String, PatternEvidence>) {
    let corpus = corpus::load_corpus().expect("corpus must load");
    let ledger = ledger::load_ledger().expect("ledger must load");
    let evidence = guard_core_conformance::corpus_patterns(&corpus)
        .into_iter()
        .map(|e| (e.pattern.clone(), e))
        .collect();
    (corpus, ledger, evidence)
}

/// The `pyregex` translation rules the engine applies before handing a
/// source to the `regex` crate, applied for fancy-regex too: `\Z` becomes
/// `\z` and a bare `$` becomes the Python end-or-trailing-newline shape.
fn translate(source: &str) -> String {
    let mut out = String::with_capacity(source.len() + 8);
    let mut chars = source.chars().peekable();
    let mut in_class = false;
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(ch);
            if let Some(&next) = chars.peek() {
                if next == 'Z' && !in_class {
                    out.pop();
                    out.push_str("\\z");
                } else {
                    out.push(next);
                }
                chars.next();
            }
            continue;
        }
        match ch {
            '[' if !in_class => {
                in_class = true;
                out.push(ch);
            }
            ']' if in_class => {
                in_class = false;
                out.push(ch);
            }
            '$' if !in_class => {
                // Python `$`: end of string, or just before a trailing
                // newline.
                out.push_str("(?:\\n?\\z)");
            }
            _ => out.push(ch),
        }
    }
    out
}

fn fancy_compile(entry: &ResidualEntry) -> Result<FancyRegex, String> {
    let translated = translate(&entry.pattern);
    let source = translated.strip_prefix("(?i)").unwrap_or(&translated);
    let ignore_case = translated.starts_with("(?i)");
    let decorated = if ignore_case {
        format!("(?i){source}")
    } else {
        source.to_owned()
    };
    FancyRegex::new(&decorated).map_err(|e| format!("fancy-regex rejected: {e}"))
}

/// Whether the entry documents a fancy-regex detection limit (the engine's
/// binary-island candidate selection on noise payloads, which a naive
/// oracle over the flat views does not reproduce).
fn has_documented_limit(entry: &ResidualEntry) -> bool {
    entry
        .fancy_regex
        .as_deref()
        .is_some_and(|verdict| verdict.contains("detection limit"))
}

#[test]
fn every_residual_pattern_compiles_under_fancy_regex() {
    let (_, ledger, _) = load();
    let mut failures = Vec::new();
    for entry in &ledger.residual {
        if let Err(e) = fancy_compile(entry) {
            failures.push(format!("[{}] {}: {e}", entry.category, entry.pattern));
        }
    }
    println!(
        "residual fancy-regex compiles: {}/{}",
        ledger.residual.len() - failures.len(),
        ledger.residual.len()
    );
    assert!(
        failures.is_empty(),
        "the lookaround/backreference residuals must compile under fancy-regex:\n{}",
        failures.join("\n")
    );
}

#[test]
fn every_residual_entry_documents_its_serving_and_oracle_verdict() {
    let (_, ledger, evidence) = load();
    let mut problems = Vec::new();
    for entry in &ledger.residual {
        if entry.served_by.as_deref() != Some("structural matcher (patterns/matchers.rs)") {
            problems.push(format!("[{}] missing served_by", entry.pattern));
        }
        let Some(verdict) = entry.fancy_regex.as_deref() else {
            problems.push(format!("[{}] missing fancy_regex verdict", entry.pattern));
            continue;
        };
        let documented_limit = verdict.contains("detection limit");
        if documented_limit && verdict.len() < 40 {
            problems.push(format!(
                "[{}] a detection limit must say what the limit is",
                entry.pattern
            ));
        }
        if !documented_limit && verdict != "verified" {
            problems.push(format!(
                "[{}] the fancy_regex verdict must be 'verified' or a detection limit",
                entry.pattern
            ));
        }
        // Nothing is ledger-only silence: every residual has corpus
        // evidence its serving covers.
        if !evidence.contains_key(&entry.pattern) {
            problems.push(format!("[{}] no corpus evidence", entry.pattern));
        }
    }
    assert!(
        problems.is_empty(),
        "the residual ledger entries must document their serving and oracle state:\n{}",
        problems.join("\n")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn residual_matchers_agree_with_the_fancy_regex_oracle() {
    let (corpus, ledger, evidence) = load();
    let knobs = map_knobs(&corpus.index.config_knobs).expect("knobs");

    // The engine's per-case regex threats (the structural matchers'
    // output the detect gate compares), plus each case's content for the
    // oracle's views.
    let mut threats_by_case: BTreeMap<String, Vec<(String, String, u64)>> = BTreeMap::new();
    let mut content_by_case: BTreeMap<String, String> = BTreeMap::new();
    for suite in &corpus.suites {
        for case in &suite.cases {
            let key = format!("{}::{}", suite.name, case.id);
            let verdict = detect::detect(&case.input.content, &case.input.context, &knobs);
            let mut threats = Vec::new();
            for threat in &verdict.threats {
                let Some(pattern) = threat.get("pattern").and_then(Value::as_str) else {
                    continue;
                };
                let Some(matched) = threat.get("match").and_then(Value::as_str) else {
                    continue;
                };
                let Some(position) = threat.get("position").and_then(Value::as_u64) else {
                    continue;
                };
                threats.push((pattern.to_owned(), matched.to_owned(), position));
            }
            threats_by_case.insert(key.clone(), threats);
            content_by_case.insert(key, case.input.content.clone());
        }
    }

    let mut agreements = 0_usize;
    let mut disagreements: Vec<String> = Vec::new();
    let mut limit_documented = 0_usize;
    for entry in &ledger.residual {
        let Ok(oracle) = fancy_compile(entry) else {
            if has_documented_limit(entry) {
                limit_documented += 1;
                continue;
            }
            disagreements.push(format!(
                "[{}] fancy-regex cannot compile and no limit is documented",
                entry.pattern
            ));
            continue;
        };
        let Some(ev) = evidence.get(&entry.pattern) else {
            disagreements.push(format!("[{}] no corpus evidence", entry.pattern));
            continue;
        };
        let limited = has_documented_limit(entry);
        for case_evidence in &ev.cases {
            let Some(engine_threats) = threats_by_case.get(&case_evidence.case) else {
                disagreements.push(format!(
                    "[{}] no engine verdict for {}",
                    entry.pattern, case_evidence.case
                ));
                continue;
            };
            // The engine's own answer for this pattern on this case (the
            // structural matcher's output the detect gate compares).
            let Some((_pattern, engine_match, engine_position)) = engine_threats
                .iter()
                .find(|(pattern, _, _)| pattern == &entry.pattern)
            else {
                disagreements.push(format!(
                    "[{}] the engine does not report the pattern on {}",
                    entry.pattern, case_evidence.case
                ));
                continue;
            };
            // The oracle answers the same views the engine scanned (the
            // detect view construction, mirrored): the processed view and
            // the raw signal-preserving view.
            let content = content_by_case
                .get(&case_evidence.case)
                .expect("case content");
            let (processed, _decoded, _) = guard_core_engine::preprocessor::preprocess_with_decoded(
                content,
                knobs.max_truncate_bytes,
                knobs.preserve_attack_patterns,
                knobs.max_content_length,
            );
            let raw_view = guard_core_engine::preprocessor::preprocess_signal_preserving(
                content,
                knobs.max_truncate_bytes,
                knobs.preserve_attack_patterns,
                knobs.max_content_length,
            );
            let views = [&processed, &raw_view];
            let oracle_answer = views.iter().find_map(|view| {
                oracle
                    .find_iter(view)
                    .next()
                    .and_then(std::result::Result::ok)
                    .map(|m| (m.as_str().to_owned(), m.start()))
            });
            match oracle_answer {
                None if limited => {
                    // The documented limit covers this disagreement: the
                    // binary-island candidate selection on noise payloads.
                    limit_documented += 1;
                }
                None => {
                    disagreements.push(format!(
                        "[{}] the oracle does not match on {} (engine: {engine_match:?})",
                        entry.pattern, case_evidence.case
                    ));
                }
                Some((oracle_match, oracle_start)) => {
                    let agrees = oracle_match == *engine_match
                        && oracle_start == usize::try_from(*engine_position).unwrap_or(usize::MAX);
                    if agrees {
                        agreements += 1;
                    } else if limited {
                        // The documented limit covers candidate-selection
                        // differences: which text the oracle picks and
                        // where, inside noise payloads.
                        limit_documented += 1;
                    } else {
                        disagreements.push(format!(
                            "[{}] {} engine ({engine_match:?}, {engine_position}) oracle ({oracle_match:?}, {oracle_start})",
                            entry.pattern, case_evidence.case
                        ));
                    }
                }
            }
        }
    }

    println!(
        "residual oracle agreements: {agreements}, limit-documented: \
         {limit_documented}, disagreements: {}",
        disagreements.len()
    );
    for disagreement in &disagreements {
        println!("  {disagreement}");
    }
    assert!(
        disagreements.is_empty(),
        "the structural residual matchers must agree with the fancy-regex \
         oracle on the corpus evidence unless the ledger documents the \
         limit ({} disagreements)",
        disagreements.len()
    );
}
