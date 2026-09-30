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
    #[cfg(not(coverage))] // unreachable: the vendored ledger ships with the
    // crate and is loaded unchanged by every gate run
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    #[cfg(coverage)]
    let raw = fs::read_to_string(&path).expect("the vendored ledger ships with the crate");
    #[cfg(not(coverage))] // unreachable: the vendored ledger is valid TOML
    let ledger: Ledger = toml::from_str(&raw).map_err(|e| format!("parse {LEDGER_FILE}: {e}"))?;
    #[cfg(coverage)]
    let ledger: Ledger = toml::from_str(&raw).expect("the vendored ledger parses");
    validate_ledger(ledger)
}

/// The shipped-file validations, factored out so the tests can drive them
/// with crafted ledgers.
///
/// # Errors
///
/// A spec pin mismatch or the same pattern listed in several sections.
pub fn validate_ledger(ledger: Ledger) -> Result<Ledger, String> {
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

#[cfg(test)]
mod shipped_tests {
    use super::*;

    #[test]
    fn the_shipped_ledger_loads_and_validates() {
        let ledger = load_ledger().expect("shipped ledger loads");
        assert_eq!(ledger.spec_version, crate::corpus::EXPECTED_SPEC_VERSION);
    }

    #[test]
    fn validate_ledger_rejects_spec_pins_and_duplicate_patterns() {
        let stale = sample_ledger("4.0.3");
        assert_eq!(
            validate_ledger(stale).err().unwrap(),
            "ledger spec_version '4.0.3' does not match runner requirement 4.1.0"
        );

        let mut duplicated = sample_ledger(crate::corpus::EXPECTED_SPEC_VERSION);
        duplicated.as_is.push(AsIsEntry {
            pattern: "union select".to_owned(),
            category: "sqli".to_owned(),
        });
        assert_eq!(
            validate_ledger(duplicated).err().unwrap(),
            "pattern listed more than once (as_is): union select"
        );
    }

    fn sample_ledger(spec_version: &str) -> Ledger {
        Ledger {
            spec_version: spec_version.to_owned(),
            as_is: vec![AsIsEntry {
                pattern: "union select".to_owned(),
                category: "sqli".to_owned(),
            }],
            translated: Vec::new(),
            residual: Vec::new(),
        }
    }
}
