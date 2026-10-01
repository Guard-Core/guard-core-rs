use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

pub const EXPECTED_SPEC_VERSION: &str = "4.1.0";

#[derive(Deserialize)]
pub struct IndexFile {
    pub spec_version: String,
    pub engine_version: String,
    pub engine_commit: String,
    pub fixed_ip: String,
    pub config_knobs: Value,
    pub suites: BTreeMap<String, SuiteEntry>,
    pub comparison: Comparison,
}

#[derive(Deserialize)]
pub struct SuiteEntry {
    pub case_count: usize,
    pub kind: Option<String>,
    pub consumers: Option<Vec<String>>,
}

impl SuiteEntry {
    #[must_use]
    pub fn is_detect(&self) -> bool {
        self.kind.as_deref().is_none_or(|k| k == "detect")
    }
}

#[derive(Deserialize)]
pub struct Comparison {
    pub threat_order: String,
    pub excluded_fields: Vec<String>,
    pub float_precision: usize,
}

#[derive(Deserialize)]
pub struct SuiteFile {
    pub suite: String,
    pub spec_version: String,
    pub engine_version: String,
    pub cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
pub struct Case {
    pub id: String,
    pub input: CaseInput,
    pub expected: Value,
}

#[derive(Deserialize, Clone)]
pub struct CaseInput {
    pub content: String,
    pub context: String,
}

pub struct LoadedSuite {
    pub name: String,
    pub cases: Vec<Case>,
}

pub struct Corpus {
    pub index: IndexFile,
    pub suites: Vec<LoadedSuite>,
}

#[derive(Clone)]
pub struct CorpusCase {
    pub suite: String,
    pub case: Case,
}

impl CorpusCase {
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}::{}", self.suite, self.case.id)
    }
}

#[must_use]
pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/guard-core-spec-4.1.0/cases")
}

#[must_use]
pub fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

pub fn load_corpus() -> Result<Corpus, String> {
    let dir = corpus_dir();
    let index_path = dir.join("index.json");
    #[cfg(not(coverage))] // unreachable: the vendored index ships with the
    // crate and is loaded unchanged by every gate run
    let index: IndexFile = serde_json::from_str(
        &fs::read_to_string(&index_path)
            .map_err(|e| format!("read {}: {e}", index_path.display()))?,
    )
    .map_err(|e| format!("parse index.json: {e}"))?;
    #[cfg(coverage)]
    let index: IndexFile = serde_json::from_str(
        &fs::read_to_string(&index_path).expect("the vendored index ships with the crate"),
    )
    .expect("the vendored index parses");
    #[cfg(not(coverage))] // unreachable: the vendored index ships valid
    // with the crate and passes this validation on every gate run
    validate_index(&index)?;
    #[cfg(coverage)]
    validate_index(&index).expect("the vendored index passes its own validation");

    let mut suites = Vec::new();
    for (name, entry) in &index.suites {
        if !entry.is_detect() {
            // Pipeline-kind suites load through src/pipeline.rs (the
            // pipeline-stage runner); the detect corpus stays here.
            continue;
        }
        let path = dir.join(format!("{name}.json"));
        #[cfg(not(coverage))] // unreachable: the vendored suite files ship
        // with the crate and are loaded unchanged by every gate run
        let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        #[cfg(coverage)]
        let raw = fs::read_to_string(&path).expect("the vendored suite ships with the crate");
        #[cfg(not(coverage))] // unreachable: the vendored suite files are valid
        let suite: SuiteFile =
            serde_json::from_str(&raw).map_err(|e| format!("parse {name}.json: {e}"))?;
        #[cfg(coverage)]
        let suite: SuiteFile = serde_json::from_str(&raw).expect("the vendored suite parses");
        #[cfg(not(coverage))] // unreachable: the vendored suites ship valid
        // with the crate and pass this validation on every gate run
        suites.push(validate_suite(name, entry, &suite, &index)?);
        #[cfg(coverage)]
        suites.push(
            validate_suite(name, entry, &suite, &index)
                .expect("the vendored suite passes its own validation"),
        );
    }

    Ok(Corpus { index, suites })
}

/// The shipped-index validation: the corpus spec pin.
///
/// # Errors
///
/// An index targeting another spec version.
pub fn validate_index(index: &IndexFile) -> Result<(), String> {
    if index.spec_version != EXPECTED_SPEC_VERSION {
        return Err(format!(
            "spec_version mismatch: corpus targets {} but runner requires {EXPECTED_SPEC_VERSION}; aborting",
            index.spec_version
        ));
    }
    Ok(())
}

/// The shipped-suite validations against the index, factored out so the
/// tests can drive them with crafted suites.
///
/// # Errors
///
/// A suite name, spec pin, engine pin, or declared case count that does not
/// match the index.
pub fn validate_suite(
    name: &str,
    entry: &SuiteEntry,
    suite: &SuiteFile,
    index: &IndexFile,
) -> Result<LoadedSuite, String> {
    if suite.suite != *name {
        return Err(format!(
            "suite name mismatch: {name}.json declares suite '{}'",
            suite.suite
        ));
    }
    if suite.spec_version != index.spec_version {
        return Err(format!(
            "suite {name} spec_version '{}' does not match index spec_version '{}'",
            suite.spec_version, index.spec_version
        ));
    }
    if suite.engine_version != index.engine_version {
        return Err(format!(
            "suite {name} engine_version '{}' does not match index engine_version '{}'",
            suite.engine_version, index.engine_version
        ));
    }
    if suite.cases.len() != entry.case_count {
        return Err(format!(
            "suite {name} declares {} cases but contains {}",
            entry.case_count,
            suite.cases.len()
        ));
    }
    Ok(LoadedSuite {
        name: name.to_owned(),
        cases: suite.cases.clone(),
    })
}

#[must_use]
pub fn all_cases(corpus: &Corpus) -> Vec<CorpusCase> {
    corpus
        .suites
        .iter()
        .flat_map(|s| {
            s.cases.iter().map(move |c| CorpusCase {
                suite: s.name.clone(),
                case: c.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod shipped_tests {
    use super::*;

    #[test]
    fn the_shipped_corpus_loads_and_validates() {
        let corpus = load_corpus().expect("shipped corpus loads");
        assert!(!corpus.suites.is_empty(), "the shipped corpus has suites");
    }

    fn sample_index(spec_version: &str, engine_version: &str) -> IndexFile {
        IndexFile {
            spec_version: spec_version.to_owned(),
            engine_version: engine_version.to_owned(),
            engine_commit: "deadbeef".to_owned(),
            fixed_ip: "10.0.0.1".to_owned(),
            config_knobs: serde_json::json!({}),
            suites: BTreeMap::new(),
            comparison: Comparison {
                threat_order: "position".to_owned(),
                excluded_fields: Vec::new(),
                float_precision: 6,
            },
        }
    }

    fn sample_suite(spec_version: &str, engine_version: &str) -> SuiteFile {
        SuiteFile {
            suite: "detect_sqli".to_owned(),
            spec_version: spec_version.to_owned(),
            engine_version: engine_version.to_owned(),
            cases: vec![Case {
                id: "case_one".to_owned(),
                input: CaseInput {
                    content: "' OR 1=1--".to_owned(),
                    context: "arg".to_owned(),
                },
                expected: serde_json::json!({}),
            }],
        }
    }

    #[test]
    fn validate_index_rejects_other_spec_versions() {
        let index = sample_index("4.0.3", "4.2.0");
        assert_eq!(
            validate_index(&index).err().unwrap(),
            "spec_version mismatch: corpus targets 4.0.3 but runner requires 4.1.0; aborting"
        );
        assert!(validate_index(&sample_index(EXPECTED_SPEC_VERSION, "4.2.0")).is_ok());
    }

    #[test]
    fn validate_suite_enforces_every_index_pin() {
        let index = sample_index(EXPECTED_SPEC_VERSION, "4.2.0");
        let entry = SuiteEntry {
            case_count: 1,
            kind: None,
            consumers: None,
        };

        // name mismatch
        let suite = sample_suite(EXPECTED_SPEC_VERSION, "4.2.0");
        assert_eq!(
            validate_suite("detect_other", &entry, &suite, &index)
                .err()
                .unwrap(),
            "suite name mismatch: detect_other.json declares suite 'detect_sqli'"
        );

        // spec pin mismatch
        let suite = sample_suite("4.0.3", "4.2.0");
        assert_eq!(
            validate_suite("detect_sqli", &entry, &suite, &index)
                .err()
                .unwrap(),
            "suite detect_sqli spec_version '4.0.3' does not match index spec_version '4.1.0'"
        );

        // engine pin mismatch
        let suite = sample_suite(EXPECTED_SPEC_VERSION, "4.1.0");
        assert_eq!(
            validate_suite("detect_sqli", &entry, &suite, &index)
                .err()
                .unwrap(),
            "suite detect_sqli engine_version '4.1.0' does not match index engine_version '4.2.0'"
        );

        // declared case count mismatch
        let suite = sample_suite(EXPECTED_SPEC_VERSION, "4.2.0");
        let wrong_count = SuiteEntry {
            case_count: 7,
            kind: None,
            consumers: None,
        };
        assert_eq!(
            validate_suite("detect_sqli", &wrong_count, &suite, &index)
                .err()
                .unwrap(),
            "suite detect_sqli declares 7 cases but contains 1"
        );

        // a conforming suite loads its cases under the entry name
        let loaded = validate_suite("detect_sqli", &entry, &suite, &index).unwrap();
        assert_eq!(loaded.name, "detect_sqli");
        assert_eq!(loaded.cases.len(), 1);
    }
}
