use std::collections::HashSet;
use std::fs;

use serde::Deserialize;

use crate::corpus::conformance_dir;

pub const BASELINE_FILE: &str = "xfail_baseline.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub spec_version: String,
    pub cases: Vec<BaselineEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineEntry {
    pub case: String,
    pub reason: String,
}

pub fn load_baseline() -> Result<Baseline, String> {
    let path = conformance_dir().join(BASELINE_FILE);
    #[cfg(not(coverage))] // unreachable: the vendored baseline ships with the
    // crate and is loaded unchanged by every gate run
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    #[cfg(coverage)]
    let raw = fs::read_to_string(&path).expect("the vendored baseline ships with the crate");
    #[cfg(not(coverage))] // unreachable: the vendored baseline is valid TOML
    let baseline: Baseline =
        toml::from_str(&raw).map_err(|e| format!("parse {BASELINE_FILE}: {e}"))?;
    #[cfg(coverage)]
    let baseline: Baseline = toml::from_str(&raw).expect("the vendored baseline parses");
    validate_baseline(baseline)
}

/// The shipped-file validations, factored out so the tests can drive them
/// with crafted baselines.
///
/// # Errors
///
/// A spec pin mismatch or the same case baselined twice.
pub fn validate_baseline(baseline: Baseline) -> Result<Baseline, String> {
    if baseline.spec_version != crate::corpus::EXPECTED_SPEC_VERSION {
        return Err(format!(
            "baseline spec_version '{}' does not match runner requirement {}",
            baseline.spec_version,
            crate::corpus::EXPECTED_SPEC_VERSION
        ));
    }

    let mut seen = HashSet::new();
    for entry in &baseline.cases {
        if !seen.insert(&entry.case) {
            return Err(format!("case baselined more than once: {}", entry.case));
        }
    }

    Ok(baseline)
}

#[must_use]
pub fn baseline_keys(baseline: &Baseline) -> HashSet<String> {
    baseline.cases.iter().map(|c| c.case.clone()).collect()
}

#[must_use]
pub fn baseline_reason<'a>(baseline: &'a Baseline, key: &str) -> Option<&'a str> {
    baseline
        .cases
        .iter()
        .find(|c| c.case == key)
        .map(|c| c.reason.as_str())
}

#[cfg(test)]
mod keys_tests {
    use super::*;

    fn sample() -> Baseline {
        Baseline {
            spec_version: crate::corpus::EXPECTED_SPEC_VERSION.to_owned(),
            cases: vec![
                BaselineEntry {
                    case: "detect::sqli::union_select".to_owned(),
                    reason: "known corpus xfail".to_owned(),
                },
                BaselineEntry {
                    case: "pipeline::body::xss_tag".to_owned(),
                    reason: "parity gap".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn baseline_keys_collect_every_case() {
        let keys = baseline_keys(&sample());
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("detect::sqli::union_select"));
        assert!(keys.contains("pipeline::body::xss_tag"));
    }

    #[test]
    fn baseline_reason_finds_entries_and_misses_cleanly() {
        let baseline = sample();
        assert_eq!(
            baseline_reason(&baseline, "detect::sqli::union_select"),
            Some("known corpus xfail")
        );
        assert_eq!(baseline_reason(&baseline, "detect::sqli::missing"), None);
    }

    #[test]
    fn the_real_baseline_loads_and_validates() {
        // The repository ships a conforming baseline; the loader must accept
        // it verbatim.
        let baseline = load_baseline().expect("shipped baseline loads");
        assert_eq!(baseline.spec_version, crate::corpus::EXPECTED_SPEC_VERSION);
    }

    #[test]
    fn validate_baseline_rejects_spec_pins_and_duplicates() {
        let mut stale = sample();
        stale.spec_version = "4.0.3".to_owned();
        assert_eq!(
            validate_baseline(stale).err().unwrap(),
            "baseline spec_version '4.0.3' does not match runner requirement 4.1.0"
        );

        let mut duplicated = sample();
        duplicated.cases.push(BaselineEntry {
            case: "detect::sqli::union_select".to_owned(),
            reason: "second entry for the same case".to_owned(),
        });
        assert_eq!(
            validate_baseline(duplicated).err().unwrap(),
            "case baselined more than once: detect::sqli::union_select"
        );

        assert_eq!(validate_baseline(sample()).unwrap().cases.len(), 2);
    }
}
