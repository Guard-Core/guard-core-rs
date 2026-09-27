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
    let index: IndexFile = serde_json::from_str(
        &fs::read_to_string(&index_path)
            .map_err(|e| format!("read {}: {e}", index_path.display()))?,
    )
    .map_err(|e| format!("parse index.json: {e}"))?;

    if index.spec_version != EXPECTED_SPEC_VERSION {
        return Err(format!(
            "spec_version mismatch: corpus targets {} but runner requires {EXPECTED_SPEC_VERSION}; aborting",
            index.spec_version
        ));
    }

    let mut suites = Vec::new();
    for (name, entry) in &index.suites {
        if !entry.is_detect() {
            // Pipeline-kind suites load through src/pipeline.rs (the
            // pipeline-stage runner); the detect corpus stays here.
            continue;
        }
        let path = dir.join(format!("{name}.json"));
        let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let suite: SuiteFile =
            serde_json::from_str(&raw).map_err(|e| format!("parse {name}.json: {e}"))?;

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
        suites.push(LoadedSuite {
            name: name.clone(),
            cases: suite.cases,
        });
    }

    Ok(Corpus { index, suites })
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
