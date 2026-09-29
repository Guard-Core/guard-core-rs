use std::collections::HashSet;
use std::fmt::Write as _;
use std::hash::BuildHasher;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passed,
    Failed,
    Xfail,
    NotRun,
}

#[derive(Debug, Clone)]
pub struct CaseResult {
    pub case: String,
    pub suite: String,
    pub status: Status,
    pub diffs: Vec<String>,
}

#[derive(Default, Debug)]
pub struct GateReport {
    pub passed: Vec<CaseResult>,
    pub failed: Vec<CaseResult>,
    pub xfail: Vec<CaseResult>,
    pub not_run: Vec<CaseResult>,
}

impl GateReport {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.passed.len() + self.failed.len() + self.xfail.len() + self.not_run.len()
    }
}

#[derive(Debug)]
pub struct Drift {
    pub unbaselined_failures: Vec<String>,
    pub stale_xfails: Vec<String>,
    pub unbaselined_not_run: Vec<String>,
}

impl Drift {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.unbaselined_failures.is_empty()
            && self.stale_xfails.is_empty()
            && self.unbaselined_not_run.is_empty()
    }

    #[must_use]
    pub fn describe(&self) -> String {
        let mut out = String::from("CONFORMANCE DRIFT (fail-closed):\n");
        if !self.unbaselined_failures.is_empty() {
            let _ = writeln!(
                out,
                "  failing cases missing from the xfail baseline ({}):",
                self.unbaselined_failures.len()
            );
            for c in &self.unbaselined_failures {
                let _ = writeln!(out, "    {c}");
            }
        }
        if !self.stale_xfails.is_empty() {
            let _ = writeln!(
                out,
                "  baselined cases that now pass; remove them from the baseline ({}):",
                self.stale_xfails.len()
            );
            for c in &self.stale_xfails {
                let _ = writeln!(out, "    {c}");
            }
        }
        if !self.unbaselined_not_run.is_empty() {
            let _ = writeln!(
                out,
                "  cases not executed and not baselined ({}):",
                self.unbaselined_not_run.len()
            );
            for c in &self.unbaselined_not_run {
                let _ = writeln!(out, "    {c}");
            }
        }
        out
    }
}

pub fn evaluate(
    results: &[CaseResult],
    baselined: &HashSet<String, impl BuildHasher>,
) -> Result<GateReport, Drift> {
    let mut report = GateReport::default();
    let mut drift = Drift {
        unbaselined_failures: Vec::new(),
        stale_xfails: Vec::new(),
        unbaselined_not_run: Vec::new(),
    };

    for result in results {
        let is_baselined = baselined.contains(&result.case);
        match result.status {
            Status::Passed => {
                if is_baselined {
                    drift.stale_xfails.push(result.case.clone());
                }
                report.passed.push(result.clone());
            }
            Status::Failed => {
                if is_baselined {
                    report.xfail.push(result.clone());
                } else {
                    drift.unbaselined_failures.push(result.case.clone());
                    report.failed.push(result.clone());
                }
            }
            Status::NotRun => {
                if !is_baselined {
                    drift.unbaselined_not_run.push(result.case.clone());
                }
                report.not_run.push(result.clone());
            }
            Status::Xfail => unreachable!("evaluate input never carries Xfail"),
        }
    }

    if drift.is_empty() {
        Ok(report)
    } else {
        Err(drift)
    }
}

#[must_use]
pub fn suite_table(report: &GateReport, suites: &[String]) -> String {
    let mut out =
        String::from("suite                        passed  failed  xfail  not_run  total\n");
    for suite in suites {
        let p = count(&report.passed, suite);
        let f = count(&report.failed, suite);
        let x = count(&report.xfail, suite);
        let n = count(&report.not_run, suite);
        let _ = writeln!(
            out,
            "{suite:<28}{p:>7}{f:>8}{x:>7}{n:>9}{:>7}",
            p + f + x + n
        );
    }
    let _ = writeln!(
        out,
        "{:<28}{:>7}{:>8}{:>7}{:>9}{:>7}",
        "TOTAL",
        report.passed.len(),
        report.failed.len(),
        report.xfail.len(),
        report.not_run.len(),
        report.total()
    );
    out
}

#[must_use]
fn count(results: &[CaseResult], suite: &str) -> usize {
    results.iter().filter(|r| r.suite == suite).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(case: &str, status: Status) -> CaseResult {
        CaseResult {
            case: case.to_owned(),
            suite: case.split("::").next().unwrap_or("s").to_owned(),
            status,
            diffs: Vec::new(),
        }
    }

    #[test]
    fn baselined_failure_is_xfail() {
        let results = vec![result("s::c1", Status::Failed)];
        let baselined = HashSet::from(["s::c1".to_owned()]);
        let report = evaluate(&results, &baselined).expect("no drift");
        assert_eq!(report.xfail.len(), 1);
        assert!(report.failed.is_empty());
    }

    #[test]
    fn unbaselined_failure_is_drift() {
        let results = vec![result("s::c1", Status::Failed)];
        let baselined = HashSet::new();
        let drift = evaluate(&results, &baselined).expect_err("must fail closed");
        assert_eq!(drift.unbaselined_failures, vec!["s::c1"]);
    }

    #[test]
    fn regression_of_previously_passing_case_is_drift() {
        let previously_passing = vec![result("s::c1", Status::Passed)];
        let baselined = HashSet::new();
        assert!(evaluate(&previously_passing, &baselined).is_ok());

        let now_failing = vec![result("s::c1", Status::Failed)];
        let drift = evaluate(&now_failing, &baselined).expect_err("regression must fail");
        assert_eq!(drift.unbaselined_failures, vec!["s::c1"]);
    }

    #[test]
    fn stale_xfail_is_drift() {
        let results = vec![result("s::c1", Status::Passed)];
        let baselined = HashSet::from(["s::c1".to_owned()]);
        let drift = evaluate(&results, &baselined).expect_err("stale baseline must fail");
        assert_eq!(drift.stale_xfails, vec!["s::c1"]);
    }

    #[test]
    fn unbaselined_not_run_is_drift() {
        let results = vec![result("s::c1", Status::NotRun)];
        let baselined = HashSet::new();
        let drift = evaluate(&results, &baselined).expect_err("gaps must fail closed");
        assert_eq!(drift.unbaselined_not_run, vec!["s::c1"]);
    }

    #[test]
    fn baselined_not_run_is_tolerated() {
        let results = vec![result("s::c1", Status::NotRun)];
        let baselined = HashSet::from(["s::c1".to_owned()]);
        let report = evaluate(&results, &baselined).expect("no drift");
        assert_eq!(report.not_run.len(), 1);
    }

    #[test]
    fn mixed_results_aggregate_four_way() {
        let results = vec![
            result("s::p", Status::Passed),
            result("s::f", Status::Failed),
            result("s::x", Status::Failed),
            result("s::n", Status::NotRun),
        ];
        let baselined = HashSet::from(["s::f".to_owned(), "s::x".to_owned(), "s::n".to_owned()]);
        let report = evaluate(&results, &baselined).expect("no drift");
        assert_eq!(report.total(), 4);
        assert_eq!(report.passed.len(), 1);
        assert_eq!(report.failed.len(), 0);
        assert_eq!(report.xfail.len(), 2);
        assert_eq!(report.not_run.len(), 1);
    }

    #[test]
    fn suite_table_counts_per_suite() {
        let report = GateReport {
            passed: vec![result("s1::a", Status::Passed)],
            failed: vec![],
            xfail: vec![result("s2::b", Status::Failed)],
            not_run: vec![],
        };
        let suites = vec!["s1".to_owned(), "s2".to_owned()];
        let table = suite_table(&report, &suites);
        assert!(table.contains("s1"));
        assert!(table.contains("TOTAL"));
        assert!(table.contains('1'));
    }
}

#[cfg(test)]
mod describe_tests {
    use super::*;

    fn result(case: &str, status: Status) -> CaseResult {
        CaseResult {
            case: case.to_owned(),
            suite: case.split("::").next().unwrap_or("s").to_owned(),
            status,
            diffs: Vec::new(),
        }
    }

    #[test]
    fn empty_drift_describes_to_the_header_only() {
        let drift = Drift {
            unbaselined_failures: Vec::new(),
            stale_xfails: Vec::new(),
            unbaselined_not_run: Vec::new(),
        };
        assert!(drift.is_empty());
        assert_eq!(drift.describe(), "CONFORMANCE DRIFT (fail-closed):\n");
    }

    #[test]
    fn describe_lists_every_drift_family() {
        let drift = Drift {
            unbaselined_failures: vec!["s::c1".to_owned(), "s::c2".to_owned()],
            stale_xfails: vec!["s::c3".to_owned()],
            unbaselined_not_run: vec!["s::c4".to_owned()],
        };
        assert!(!drift.is_empty());
        let described = drift.describe();
        assert!(described.contains("failing cases missing from the xfail baseline (2)"));
        assert!(described.contains("s::c1"));
        assert!(
            described.contains("baselined cases that now pass; remove them from the baseline (1)")
        );
        assert!(described.contains("s::c3"));
        assert!(described.contains("cases not executed and not baselined (1)"));
        assert!(described.contains("s::c4"));
    }

    #[test]
    fn not_run_cases_land_in_drift_and_the_not_run_bucket() {
        let results = vec![result("s::c1", Status::NotRun)];
        let drift = evaluate(&results, &HashSet::new()).expect_err("unbaselined not-run is drift");
        assert_eq!(drift.unbaselined_not_run, vec!["s::c1"]);

        let baselined = HashSet::from(["s::c1".to_owned()]);
        let report = evaluate(&results, &baselined).expect("baselined not-run is fine");
        assert_eq!(report.not_run.len(), 1);
    }

    #[test]
    fn stale_xfail_and_mixed_results_aggregate() {
        let results = vec![
            result("s::c1", Status::Passed),
            result("s::c2", Status::Failed),
            result("s::c4", Status::NotRun),
        ];
        let baselined = HashSet::from(["s::c1".to_owned()]);
        let drift = evaluate(&results, &baselined).expect_err("stale xfail plus failure");
        assert_eq!(drift.stale_xfails, vec!["s::c1"]);
        assert_eq!(drift.unbaselined_failures, vec!["s::c2"]);
        assert_eq!(drift.unbaselined_not_run, vec!["s::c4"]);
    }

    #[test]
    fn suite_table_counts_per_suite_and_totals() {
        let report = GateReport {
            passed: vec![result("alpha::c1", Status::Passed)],
            failed: vec![
                result("alpha::c2", Status::Failed),
                result("beta::c3", Status::Failed),
            ],
            xfail: Vec::new(),
            not_run: Vec::new(),
        };
        let table = suite_table(&report, &["alpha".to_owned(), "beta".to_owned()]);
        assert!(table.contains("alpha"));
        assert!(table.contains("beta"));
        assert!(table.contains("TOTAL"));
        let total_row = table.lines().last().unwrap_or("");
        assert!(total_row.contains('1'), "one passed: {total_row}");
        assert!(total_row.contains('2'), "two failed: {total_row}");
    }
}

#[cfg(test)]
mod evaluate_tests {
    use super::*;

    #[test]
    #[should_panic(expected = "evaluate input never carries Xfail")]
    fn evaluate_refuses_xfail_inputs() {
        // the runner resolves xfails before aggregation, so an Xfail result
        // here is a runner bug: evaluate refuses it
        let results = vec![CaseResult {
            case: "detect::sqli::union_select".to_owned(),
            suite: "detect_sqli".to_owned(),
            status: Status::Xfail,
            diffs: Vec::new(),
        }];
        let _ = evaluate(&results, &HashSet::new());
    }
}
