//! Killable probe subprocesses.
//!
//! The reference times untrusted patterns in `python -c` children so a
//! runaway loop can be killed; this port self-execs this crate's
//! `guard-pattern-probe` binary with a hidden subcommand and speaks JSON
//! on stdin/stdout. A runaway `fancy-regex` backtracking loop cannot be
//! interrupted in-process, so every timing probe runs in a child we can
//! kill on deadline.
//!
//! Parent side: [`run_child_request`] spawns and enforces the deadline.
//! Child side: [`child_main`] is wired into the binary target
//! `guard-pattern-probe`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::ast::Flags;

/// Hidden subcommand name the child dispatches on.
pub const SUBCOMMAND: &str = "__guard_pattern_probe";

/// The large-sample early-exit threshold (reference
/// `_REACH_PROBE_LARGE_SAMPLE_SECONDS`).
pub const LARGE_SAMPLE_SECONDS: f64 = 0.2;

const REFERENCE_SCAN_PATTERN: &str =
    r"(?i)/[0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b";
const REFERENCE_SCAN_PROBE_LENGTH: usize = 32000;

/// What the parent asks the child to do.
#[derive(Debug, Clone)]
pub enum ChildRequest {
    /// The pattern-safety probe: search every test string under a
    /// per-string threshold.
    TestStrings {
        pattern: String,
        test_strings: Vec<String>,
        threshold: f64,
        flags: Flags,
    },
    /// The reach-probe timing ladder.
    ReachTiming {
        pattern: String,
        probes: Vec<String>,
        samples: usize,
        deadline: f64,
        flags: Flags,
        trigger: f64,
    },
    /// The reference scan, for host-load normalization.
    ReferenceLoad,
    /// Stray verification: the first candidate every probe fails on.
    StrayVerify {
        pattern: String,
        flags: Flags,
        cases: Vec<(String, Vec<String>)>,
    },
}

/// Decoded child output.
#[derive(Debug, Clone, PartialEq)]
pub enum ChildOutcome {
    /// `{"safe": bool, "reason": str}` from the pattern-safety probe.
    Safety { safe: bool, reason: String },
    /// `{"results": [[...]], "reference": float}` from reach timing.
    Timing {
        results: Vec<Vec<f64>>,
        reference: f64,
    },
    /// `{"reference": float}` from the load probe.
    Reference { reference: f64 },
    /// The chosen stray candidate (or none).
    Stray(Option<String>),
    /// `{"error": str}` from a reach-timing compile failure.
    Failed(String),
}

/// Spawn failures the parent maps to reference exception text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildSpawnError {
    /// The deadline elapsed; the child was killed.
    Timeout,
    /// The child could not be spawned or exited unexpectedly.
    Failed(String),
}

impl std::fmt::Display for ChildSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "child deadline elapsed"),
            Self::Failed(detail) => write!(f, "child failed: {detail}"),
        }
    }
}

impl std::error::Error for ChildSpawnError {}

fn flags_value(flags: &Flags) -> Value {
    json!({
        "i": flags.ignorecase,
        "m": flags.multiline,
        "s": flags.dotall,
        "a": flags.ascii,
    })
}

fn flags_from_value(value: &Value) -> Flags {
    Flags {
        ignorecase: value.get("i").and_then(Value::as_bool).unwrap_or_default(),
        multiline: value.get("m").and_then(Value::as_bool).unwrap_or_default(),
        dotall: value.get("s").and_then(Value::as_bool).unwrap_or_default(),
        ascii: value.get("a").and_then(Value::as_bool).unwrap_or_default(),
    }
}

fn request_payload(request: &ChildRequest) -> Value {
    match request {
        ChildRequest::TestStrings {
            pattern,
            test_strings,
            threshold,
            flags,
        } => json!({
            "op": "test_strings",
            "pattern": pattern,
            "test_strings": test_strings,
            "threshold": threshold,
            "flags": flags_value(flags),
        }),
        ChildRequest::ReachTiming {
            pattern,
            probes,
            samples,
            deadline,
            flags,
            trigger,
        } => json!({
            "op": "reach_timing",
            "pattern": pattern,
            "probes": probes,
            "samples": samples,
            "deadline": deadline,
            "flags": flags_value(flags),
            "trigger": trigger,
        }),
        ChildRequest::ReferenceLoad => json!({ "op": "reference_load" }),
        ChildRequest::StrayVerify {
            pattern,
            flags,
            cases,
        } => json!({
            "op": "stray_verify",
            "pattern": pattern,
            "flags": flags_value(flags),
            "cases": cases
                .iter()
                .map(|(candidate, probes)| json!([candidate, probes]))
                .collect::<Vec<_>>(),
        }),
    }
}

fn parse_outcome(stdout: &str) -> Result<ChildOutcome, ChildSpawnError> {
    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|e| ChildSpawnError::Failed(format!("malformed child output: {e}")))?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Ok(ChildOutcome::Failed(error.to_owned()));
    }
    if let (Some(safe), Some(reason)) = (
        value.get("safe").and_then(Value::as_bool),
        value.get("reason").and_then(Value::as_str),
    ) {
        return Ok(ChildOutcome::Safety {
            safe,
            reason: reason.to_owned(),
        });
    }
    if let Some(reference) = value.get("reference").and_then(Value::as_f64) {
        if let Some(results) = value.get("results") {
            let rows: Vec<Vec<f64>> = results
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .map(|row| {
                            row.as_array()
                                .map(|samples| {
                                    samples
                                        .iter()
                                        .filter_map(Value::as_f64)
                                        .collect::<Vec<f64>>()
                                })
                                .unwrap_or_default()
                        })
                        .collect()
                })
                .unwrap_or_default();
            return Ok(ChildOutcome::Timing {
                results: rows,
                reference,
            });
        }
        return Ok(ChildOutcome::Reference { reference });
    }
    if let Some(candidate) = value.as_str() {
        return Ok(ChildOutcome::Stray(Some(candidate.to_owned())));
    }
    if value.is_null() {
        return Ok(ChildOutcome::Stray(None));
    }
    Err(ChildSpawnError::Failed(format!(
        "malformed child output: {value}"
    )))
}

/// Locate the probe child binary.
#[must_use]
pub fn child_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("GUARD_PATTERN_PROBE_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let exe_name = exe.file_name()?.to_str()?;
    if exe_name.starts_with("guard-pattern-probe") {
        return Some(exe);
    }
    let dir = exe.parent()?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for name in ["guard-pattern-probe", "guard-pattern-probe.exe"] {
        candidates.push(dir.join(name));
    }
    if let Some(parent) = dir.parent() {
        // Unit tests run from target/debug/deps; the sibling binary is in
        // target/debug.
        for name in ["guard-pattern-probe", "guard-pattern-probe.exe"] {
            candidates.push(parent.join(name));
        }
    }
    candidates.into_iter().find(|candidate| candidate.exists())
}

/// Run a child request under `timeout_secs`, killing the child on the
/// deadline.
///
/// # Errors
///
/// [`ChildSpawnError`] on deadline or spawn/exit failure.
pub fn run_child_request(
    request: &ChildRequest,
    timeout_secs: f64,
) -> Result<ChildOutcome, ChildSpawnError> {
    let payload = request_payload(request).to_string();
    let Some(child_path) = child_path() else {
        return Err(ChildSpawnError::Failed(
            "probe child binary not found".into(),
        ));
    };
    let mut command = Command::new(&child_path);
    command
        .arg(SUBCOMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| ChildSpawnError::Failed(format!("spawn failed: {e}")))?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        thread::spawn(move || {
            let _ = stdin.write_all(payload.as_bytes());
        });
    }
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let reader = thread::spawn(move || {
        let mut buffer = String::new();
        let _ = stdout_pipe.read_to_string(&mut buffer);
        buffer
    });
    let start = Instant::now();
    let deadline = Duration::from_secs_f64(timeout_secs.max(0.0));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(ChildSpawnError::Failed(format!("wait failed: {e}"))),
        }
    };
    let output = reader.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(ChildSpawnError::Timeout);
    };
    if !status.success() || output.trim().is_empty() {
        return Err(ChildSpawnError::Failed(format!(
            "child exited unexpectedly (status {status})"
        )));
    }
    parse_outcome(&output)
}

fn flag_prefix(flags: &Flags) -> String {
    let mut letters = String::new();
    if flags.ignorecase {
        letters.push('i');
    }
    if flags.multiline {
        letters.push('m');
    }
    if flags.dotall {
        letters.push('s');
    }
    if flags.ascii {
        letters.push('a');
    }
    if letters.is_empty() {
        String::new()
    } else {
        format!("(?{letters})")
    }
}

/// The compiled engine the child times with: `regex` where the pattern
/// compiles, `fancy-regex` for fancy-only constructs.
pub enum CompiledProbe {
    Re(regex::Regex),
    Fancy(fancy_regex::Regex),
}

impl CompiledProbe {
    /// Compile with the crate the engine will actually execute.
    ///
    /// # Errors
    ///
    /// The first engine's error text when both fail.
    pub fn compile(pattern: &str, flags: &Flags) -> Result<Self, String> {
        let source = format!("{}{pattern}", flag_prefix(flags));
        if let Ok(regex) = regex::Regex::new(&source) {
            return Ok(Self::Re(regex));
        }
        fancy_regex::Regex::new(&source)
            .map(Self::Fancy)
            .map_err(|e| e.to_string())
    }

    /// One search pass, returning wall time.
    pub fn timed_search(&self, text: &str) -> f64 {
        let start = Instant::now();
        match self {
            Self::Re(regex) => {
                let _ = regex.find(text);
            }
            Self::Fancy(regex) => {
                let _ = regex.find(text);
            }
        }
        start.elapsed().as_secs_f64()
    }
}

fn reference_scan_times(samples: usize) -> Vec<f64> {
    let Ok(reference) = CompiledProbe::compile(REFERENCE_SCAN_PATTERN, &Flags::default()) else {
        return Vec::new();
    };
    let probe = format!("/{}", "0".repeat(REFERENCE_SCAN_PROBE_LENGTH));
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        times.push(reference.timed_search(&probe));
    }
    times
}

fn child_test_strings(payload: &Value) -> Value {
    let pattern = payload["pattern"].as_str().unwrap_or_default();
    let test_strings: Vec<&str> = payload["test_strings"]
        .as_array()
        .map(|rows| rows.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let threshold = payload["threshold"].as_f64().unwrap_or(f64::MAX);
    let flags = flags_from_value(&payload["flags"]);
    let compiled = match CompiledProbe::compile(pattern, &flags) {
        Ok(compiled) => compiled,
        Err(message) => {
            return json!({
                "safe": false,
                "reason": format!("Pattern validation failed: {message}"),
            });
        }
    };
    for test_str in test_strings {
        let elapsed = compiled.timed_search(test_str);
        if elapsed > threshold {
            return json!({
                "safe": false,
                "reason": format!(
                    "Pattern timed out on test string of length {}",
                    test_str.chars().count()
                ),
            });
        }
    }
    json!({ "safe": true, "reason": "Pattern appears safe" })
}

fn child_reach_timing(payload: &Value) -> Value {
    let pattern = payload["pattern"].as_str().unwrap_or_default();
    let probes: Vec<&str> = payload["probes"]
        .as_array()
        .map(|rows| rows.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let samples = payload["samples"].as_u64().unwrap_or(1).max(1) as usize;
    let trigger = payload["trigger"].as_f64().unwrap_or(f64::MAX);
    let flags = flags_from_value(&payload["flags"]);
    let compiled = match CompiledProbe::compile(pattern, &flags) {
        Ok(compiled) => compiled,
        Err(message) => return json!({ "error": message }),
    };
    let mut reference_times = reference_scan_times(samples);
    reference_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let reference = reference_times.first().copied().unwrap_or(0.0);
    let mut results: Vec<Vec<f64>> = Vec::with_capacity(probes.len());
    for probe in probes {
        let mut probe_times = vec![compiled.timed_search(probe)];
        if probe_times[0] >= trigger {
            for _ in 0..samples.saturating_sub(1) {
                probe_times.push(compiled.timed_search(probe));
                if *probe_times.last().expect("just pushed") > LARGE_SAMPLE_SECONDS {
                    break;
                }
            }
        }
        probe_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        results.push(probe_times);
    }
    json!({ "results": results, "reference": reference })
}

fn child_reference_load() -> Value {
    let mut reference_times = reference_scan_times(5);
    reference_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    json!({ "reference": reference_times.first().copied().unwrap_or(0.0) })
}

fn child_stray_verify(payload: &Value) -> Value {
    let pattern = payload["pattern"].as_str().unwrap_or_default();
    let flags = flags_from_value(&payload["flags"]);
    let Ok(compiled) = CompiledProbe::compile(pattern, &flags) else {
        return Value::Null;
    };
    let Some(cases) = payload["cases"].as_array() else {
        return Value::Null;
    };
    for case in cases {
        let candidate = case[0].as_str().unwrap_or_default();
        let probes = case[1].as_array().cloned().unwrap_or_default();
        let all_miss = probes
            .iter()
            .all(|probe| search_misses(&compiled, probe.as_str().unwrap_or_default()));
        if all_miss {
            return json!(candidate);
        }
    }
    Value::Null
}

fn search_misses(compiled: &CompiledProbe, probe: &str) -> bool {
    match compiled {
        CompiledProbe::Re(regex) => !regex.is_match(probe),
        CompiledProbe::Fancy(regex) => !regex.is_match(probe).unwrap_or(false),
    }
}

/// Child entry: dispatch the hidden subcommand. Returns the process exit
/// code; `None` when `args` is not the probe subcommand.
pub fn child_main(args: &[String]) -> Option<i32> {
    if args.len() < 2 || args[1] != SUBCOMMAND {
        return None;
    }
    let mut payload = String::new();
    if std::io::stdin().read_to_string(&mut payload).is_err() {
        return Some(1);
    }
    let Ok(value) = serde_json::from_str::<Value>(&payload) else {
        return Some(1);
    };
    let output = match value["op"].as_str() {
        Some("test_strings") => child_test_strings(&value),
        Some("reach_timing") => child_reach_timing(&value),
        Some("reference_load") => child_reference_load(),
        Some("stray_verify") => child_stray_verify(&value),
        _ => Value::Null,
    };
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(output.to_string().as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::cost_arbiter::REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS;

    #[test]
    fn child_path_resolves_inside_the_workspace_target_dir() {
        // Under cargo test the sibling binary sits in target/debug.
        let path = child_path().expect("child binary resolvable");
        assert!(path.exists(), "{}", path.display());
    }

    #[test]
    fn flags_round_trip_through_json() {
        let flags = Flags {
            ignorecase: true,
            multiline: false,
            dotall: true,
            ascii: false,
        };
        let decoded = flags_from_value(&flags_value(&flags));
        assert_eq!(decoded, flags);
        assert_eq!(flags_from_value(&json!({})), Flags::default());
    }

    #[test]
    fn flag_prefix_omits_an_empty_group() {
        assert_eq!(flag_prefix(&Flags::default()), "");
        assert_eq!(flag_prefix(&Flags::ignorecase_multiline()), "(?im)");
        let dotall = Flags {
            dotall: true,
            ..Flags::default()
        };
        assert_eq!(flag_prefix(&dotall), "(?s)");
    }

    #[test]
    fn parse_outcome_maps_every_child_shape() {
        let safety =
            parse_outcome(r#"{"safe": true, "reason": "Pattern appears safe"}"#).expect("outcome");
        assert!(matches!(
            safety,
            ChildOutcome::Safety {
                safe: true,
                reason: _
            }
        ));
        let error = parse_outcome(r#"{"error": "bad pattern"}"#).expect("outcome");
        assert_eq!(error, ChildOutcome::Failed("bad pattern".to_owned()));
        let reference = parse_outcome(r#"{"reference": 0.5}"#).expect("outcome");
        assert_eq!(reference, ChildOutcome::Reference { reference: 0.5 });
        let timing =
            parse_outcome(r#"{"results": [[0.2, 0.1]], "reference": 0.01}"#).expect("outcome");
        assert_eq!(
            timing,
            ChildOutcome::Timing {
                results: vec![vec![0.2, 0.1]],
                reference: 0.01,
            }
        );
        let stray = parse_outcome(r#""\u0000""#).expect("outcome");
        assert!(matches!(stray, ChildOutcome::Stray(Some(_))));
        let none = parse_outcome("null").expect("outcome");
        assert_eq!(none, ChildOutcome::Stray(None));
        assert!(parse_outcome("not json").is_err());
        assert!(parse_outcome("{}").is_err());
    }

    #[test]
    fn timed_search_falls_back_to_fancy_regex() {
        // Lookarounds only compile under fancy-regex.
        let compiled = CompiledProbe::compile("(?!x)a", &Flags::default()).expect("fancy compile");
        assert!(matches!(compiled, CompiledProbe::Fancy(_)));
        assert!(compiled.timed_search("ab") > 0.0);
    }

    #[test]
    fn compile_reports_the_engine_error_text() {
        let error = CompiledProbe::compile("[invalid", &Flags::default())
            .err()
            .expect("compile error");
        assert!(!error.is_empty());
    }

    #[test]
    fn run_child_request_kills_a_runaway_child() {
        // A deadline under the process-spawn floor deterministically
        // exercises the kill path: the parent polls, kills, waits, and
        // reports a timeout instead of blocking forever on a child that
        // cannot be interrupted in-process.
        let start = Instant::now();
        let outcome = run_child_request(&ChildRequest::ReferenceLoad, 0.0005);
        assert!(
            matches!(outcome, Err(ChildSpawnError::Timeout)),
            "expected a killed child, got {outcome:?}"
        );
        assert!(
            start.elapsed().as_secs_f64() < 5.0,
            "the kill must be prompt"
        );
    }

    #[test]
    fn reference_load_child_reports_a_positive_scan() {
        let outcome = run_child_request(
            &ChildRequest::ReferenceLoad,
            REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS,
        )
        .expect("reference load");
        let ChildOutcome::Reference { reference } = outcome else {
            panic!("expected a reference measurement");
        };
        assert!(reference > 0.0);
    }

    #[test]
    fn compiled_probe_uses_the_regex_crate_first() {
        let compiled = CompiledProbe::compile("abc", &Flags::default()).expect("compile");
        assert!(matches!(compiled, CompiledProbe::Re(_)));
    }
}
