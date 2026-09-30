use std::fs;

use serde::Deserialize;

use crate::corpus::conformance_dir;

pub const LEDGER_FILE: &str = "pattern_ledger.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub spec_version: String,
    #[serde(default)]
    pub as_is: Vec<AsIsEntry>,
    #[serde(default)]
    pub translated: Vec<TranslatedEntry>,
    #[serde(default)]
    pub residual: Vec<ResidualEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsIsEntry {
    pub pattern: String,
    pub category: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslatedEntry {
    pub pattern: String,
    pub category: String,
    pub translation: String,
    pub construct: String,
    pub verified_on: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualEntry {
    pub pattern: String,
    pub category: String,
    pub constructs: Vec<String>,
    pub affected_suites: Vec<String>,
    pub evidence_cases: Vec<String>,
    /// The engine surface that serves the residual (`structural matcher`).
    #[serde(default)]
    pub served_by: Option<String>,
    /// The fancy-regex oracle verdict: `verified`, or the documented
    /// detection limit where the naive oracle disagrees.
    #[serde(default)]
    pub fancy_regex: Option<String>,
}

pub fn load_ledger() -> Result<Ledger, String> {
    let path = conformance_dir().join(LEDGER_FILE);
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let ledger: Ledger = toml::from_str(&raw).map_err(|e| format!("parse {LEDGER_FILE}: {e}"))?;

    if ledger.spec_version != crate::corpus::EXPECTED_SPEC_VERSION {
        return Err(format!(
            "ledger spec_version '{}' does not match runner requirement {}",
            ledger.spec_version,
            crate::corpus::EXPECTED_SPEC_VERSION
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for (state, pattern) in ledger
        .as_is
        .iter()
        .map(|e| ("as_is", &e.pattern))
        .chain(ledger.translated.iter().map(|e| ("translated", &e.pattern)))
        .chain(ledger.residual.iter().map(|e| ("residual", &e.pattern)))
    {
        if !seen.insert(pattern) {
            return Err(format!(
                "pattern listed more than once ({state}): {pattern}"
            ));
        }
    }

    Ok(ledger)
}
