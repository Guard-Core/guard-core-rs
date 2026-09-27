use std::collections::BTreeMap;
use std::collections::HashSet;

use guard_core_conformance::corpus::{self, Corpus};
use guard_core_conformance::ledger::{self, Ledger};
use guard_core_conformance::{PatternEvidence, corpus_patterns};
use guard_core_engine::preprocessor;
use regex::Regex;

fn load() -> (Corpus, Ledger) {
    let corpus = corpus::load_corpus().expect("corpus must load and target spec 4.1.0");
    let ledger = ledger::load_ledger().expect("ledger must load");
    (corpus, ledger)
}

fn evidence_map(corpus: &Corpus) -> BTreeMap<String, PatternEvidence> {
    corpus_patterns(corpus)
        .into_iter()
        .map(|e| (e.pattern.clone(), e))
        .collect()
}

#[test]
fn ledger_covers_every_corpus_pattern_in_exactly_one_state() {
    let (corpus, ledger) = load();
    let evidence = evidence_map(&corpus);

    let as_is: HashSet<&str> = ledger.as_is.iter().map(|e| e.pattern.as_str()).collect();
    let translated: HashSet<&str> = ledger
        .translated
        .iter()
        .map(|e| e.pattern.as_str())
        .collect();
    let residual: HashSet<&str> = ledger.residual.iter().map(|e| e.pattern.as_str()).collect();

    let mut problems = Vec::new();
    for pattern in evidence.keys() {
        let states = [
            as_is.contains(pattern.as_str()),
            translated.contains(pattern.as_str()),
            residual.contains(pattern.as_str()),
        ];
        let covered = states.iter().filter(|&&s| s).count();
        if covered == 0 {
            problems.push(format!("UNCLASSIFIED: {pattern}"));
        } else if covered > 1 {
            problems.push(format!("MULTIPLE STATES: {pattern}"));
        }
    }
    for (state, set) in [
        ("as_is", &as_is),
        ("translated", &translated),
        ("residual", &residual),
    ] {
        for pattern in set {
            if !evidence.contains_key(*pattern) {
                problems.push(format!("LEDGER-ONLY (not in corpus) [{state}]: {pattern}"));
            }
        }
    }

    println!(
        "ledger stats: as_is={} translated={} residual={} corpus={}",
        as_is.len(),
        translated.len(),
        residual.len(),
        evidence.len()
    );
    assert!(
        problems.is_empty(),
        "ledger integrity violated ({} problems):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn as_is_patterns_compile_unchanged() {
    let (_, ledger) = load();
    let mut failures = Vec::new();
    for entry in &ledger.as_is {
        if let Err(e) = Regex::new(&entry.pattern) {
            failures.push(format!("[{}] {}: {e}", entry.category, entry.pattern));
        }
    }
    println!("as-is compiled: {}", ledger.as_is.len() - failures.len());
    assert!(
        failures.is_empty(),
        "as-is patterns must compile unchanged:\n{}",
        failures.join("\n")
    );
}

#[test]
fn translated_patterns_compile_and_reproduce_corpus_evidence() {
    let (corpus, ledger) = load();
    let evidence = evidence_map(&corpus);

    let mut failures = Vec::new();
    for entry in &ledger.translated {
        let translated = match Regex::new(&format!("(?i){}", entry.translation)) {
            Ok(re) => re,
            Err(e) => {
                failures.push(format!(
                    "translation does not compile: {}: {e}",
                    entry.translation
                ));
                continue;
            }
        };

        let Some(ev) = evidence.get(&entry.pattern) else {
            failures.push(format!("no corpus evidence for {}", entry.pattern));
            continue;
        };

        let ledger_cases: HashSet<String> = entry.verified_on.iter().cloned().collect();
        let corpus_cases: HashSet<String> = ev.cases.iter().map(|c| c.case.clone()).collect();
        if ledger_cases != corpus_cases {
            failures.push(format!(
                "verified_on does not match corpus evidence for {}: ledger {:?} corpus {:?}",
                entry.pattern, entry.verified_on, corpus_cases
            ));
            continue;
        }

        for case_ev in &ev.cases {
            let case = find_case(&corpus, &case_ev.case);
            let content = &case.input.content;

            let processed = preprocessor::preprocess(content, 10_000, true);
            let raw_signal = preprocessor::normalize_unicode(content);

            let haystacks: Vec<(&str, &str)> = vec![
                ("processed", processed.as_str()),
                ("raw_signal", raw_signal.as_str()),
                ("raw", content.as_str()),
            ];

            let mut verified = false;
            let mut attempts = Vec::new();
            for (name, haystack) in &haystacks {
                for m in translated.find_iter(haystack) {
                    // this test runs the translated regex directly (not the
                    // engine), so the corpus's code-point positions must be
                    // derived from the regex crate's byte spans here
                    let char_index = haystack[..m.start()].chars().count();
                    attempts.push(format!("{name}: '{}'@{char_index}", m.as_str()));
                    if m.as_str() == case_ev.matched && char_index as u64 == case_ev.position {
                        verified = true;
                    }
                }
            }

            if !verified {
                failures.push(format!(
                    "case {} does not reproduce recorded match '{}'@{} for pattern {}; produced: {}",
                    case_ev.case, case_ev.matched, case_ev.position, entry.pattern, attempts.join(", ")
                ));
            }
        }
    }

    println!(
        "translated verified: {}",
        ledger.translated.len() - failures.len()
    );
    assert!(
        failures.is_empty(),
        "translated patterns must compile and reproduce corpus evidence:\n{}",
        failures.join("\n")
    );
}

#[test]
fn residual_patterns_are_rejected_by_regex_crate() {
    let (_, ledger) = load();
    let mut stale = Vec::new();
    for entry in &ledger.residual {
        if Regex::new(&entry.pattern).is_ok() {
            stale.push(format!(
                "residual pattern now compiles with the regex crate; reclassify as-is: {}",
                entry.pattern
            ));
        }
    }
    println!(
        "residual confirmed rejected: {}",
        ledger.residual.len() - stale.len()
    );
    assert!(stale.is_empty(), "{}", stale.join("\n"));
}

fn find_case<'a>(corpus: &'a Corpus, key: &str) -> &'a corpus::Case {
    let (suite, id) = key.split_once("::").expect("case key is suite::id");
    corpus
        .suites
        .iter()
        .find(|s| s.name == suite)
        .and_then(|s| s.cases.iter().find(|c| c.id == id))
        .unwrap_or_else(|| panic!("case {key} not found in corpus"))
}
