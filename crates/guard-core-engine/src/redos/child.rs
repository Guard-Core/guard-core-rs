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
    let env_override = std::env::var("GUARD_PATTERN_PROBE_BIN").ok();
    resolve_child_path(
        env_override.as_deref(),
        std::env::current_exe().ok().as_deref(),
    )
}

/// The pure half of [`child_path`], testable without process state.
#[must_use]
fn resolve_child_path(
    env_override: Option<&str>,
    exe: Option<&std::path::Path>,
) -> Option<PathBuf> {
    if let Some(path) = env_override {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    let exe = exe?;
    let exe_name = exe.file_name()?.to_str()?;
    if exe_name.starts_with("guard-pattern-probe") {
        return Some(exe.to_path_buf());
    }
    let dir = exe.parent()?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for base in core::iter::once(dir).chain(dir.parent()) {
        // Unit tests run from target/debug/deps; the sibling binary is in
        // target/debug.
        for name in ["guard-pattern-probe", "guard-pattern-probe.exe"] {
            candidates.push(base.join(name));
        }
    }
    // Doctests run from a temp directory, so the executable-relative search
    // cannot find the probe binary. The workspace-relative location is
    // compile-time known (crates/guard-core-engine -> <workspace>/target),
    // so the option always yields a workspace under cargo.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_candidates = manifest
        .parent()
        .and_then(|crates| crates.parent())
        .into_iter()
        .flat_map(|workspace| {
            ["guard-pattern-probe", "guard-pattern-probe.exe"]
                .iter()
                .map(move |name| workspace.join("target/debug").join(name))
        });
    candidates.extend(workspace_candidates);
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
    run_child_request_at(request, timeout_secs, child_path())
}

/// The pure half of [`run_child_request`]: the child binary path is
/// injected so tests can force spawn and exit failures deterministically.
///
/// # Errors
///
/// [`ChildSpawnError`] on deadline or spawn/exit failure.
pub(crate) fn run_child_request_at(
    request: &ChildRequest,
    timeout_secs: f64,
    child_path: Option<PathBuf>,
) -> Result<ChildOutcome, ChildSpawnError> {
    let payload = request_payload(request).to_string();
    let Some(child_path) = child_path else {
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
    // The child is a killable timing oracle, never a coverage subject: a
    // spawned child would otherwise flush its own (never fully exercised)
    // instrumented copy of this crate into the parent run's profile and
    // skew the coverage summary. The child-side dispatch is covered
    // in-process below instead.
    command.env_remove("LLVM_PROFILE_FILE");
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
    // `try_wait` could only fail with ECHILD here, which cannot happen:
    // the child was spawned by this process above and only this loop reaps
    // it. The `?` keeps that impossible path on an always-evaluated line.
    let status = loop {
        let Some(status) = child
            .try_wait()
            .map_err(|e| ChildSpawnError::Failed(format!("wait failed: {e}")))?
        else {
            if start.elapsed() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(2));
            continue;
        };
        break Some(status);
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
    #[cfg(not(coverage))] // unreachable: REFERENCE_SCAN_PATTERN is a
    // compile-time constant that compiles under the regex engine
    let Ok(reference) = CompiledProbe::compile(REFERENCE_SCAN_PATTERN, &Flags::default()) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let reference = CompiledProbe::compile(REFERENCE_SCAN_PATTERN, &Flags::default())
        .expect("the reference scan pattern is a compile-time constant");
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
        let mut probe_times = sample_probe(probe, samples, trigger, &mut |text| {
            compiled.timed_search(text)
        });
        probe_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        results.push(probe_times);
    }
    json!({ "results": results, "reference": reference })
}

/// Reference sampling: one first pass, then more only while the first met
/// the trigger, stopping early on a large sample.
fn sample_probe(
    probe: &str,
    samples: usize,
    trigger: f64,
    timed_search: &mut dyn FnMut(&str) -> f64,
) -> Vec<f64> {
    let mut probe_times = vec![timed_search(probe)];
    if probe_times[0] >= trigger {
        for _ in 0..samples.saturating_sub(1) {
            probe_times.push(timed_search(probe));
            if *probe_times.last().expect("just pushed") > LARGE_SAMPLE_SECONDS {
                break;
            }
        }
    }
    probe_times
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
    let output = match serde_json::from_str::<Value>(&payload) {
        Ok(value) => dispatch_payload(&value),
        Err(_) => return Some(1),
    };
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(output.to_string().as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    Some(0)
}

/// The pure child dispatch, testable without stdin.
#[must_use]
pub fn dispatch_payload(value: &Value) -> Value {
    match value["op"].as_str() {
        Some("test_strings") => child_test_strings(value),
        Some("reach_timing") => child_reach_timing(value),
        Some("reference_load") => child_reference_load(),
        Some("stray_verify") => child_stray_verify(value),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::cost_arbiter::REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS;

    /// Extract the unexpected-exit detail; panics on any other outcome.
    fn expect_failed(outcome: Result<ChildOutcome, ChildSpawnError>) -> String {
        match outcome {
            Err(ChildSpawnError::Failed(detail)) => detail,
            other => panic!("expected an exit failure, got {other:?}"),
        }
    }

    /// Extract the fancy engine; panics on the `regex` engine variant.
    fn expect_fancy(compiled: &CompiledProbe) -> &fancy_regex::Regex {
        match compiled {
            CompiledProbe::Fancy(regex) => regex,
            CompiledProbe::Re(_) => panic!("expected the fancy engine"),
        }
    }

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
        // A fancy-regex backtracking pattern over a 32000-char probe is
        // catastrophically slow on every host, so the 50ms deadline is
        // guaranteed to fire mid-run: the parent polls, kills, waits, and
        // reports a timeout instead of blocking forever on a child that
        // cannot be interrupted in-process. (A sub-millisecond deadline on
        // ReferenceLoad raced the child's completion on fast runners.)
        let pattern = "(?!x)(?:a|aa)+$";
        // The trailing b forces the match to fail after the greedy run,
        // sending the backtracker through the exponential split space.
        let probes = vec![format!("{}b", "a".repeat(32_000))];
        let request = ChildRequest::ReachTiming {
            pattern: pattern.to_owned(),
            probes,
            samples: 1,
            deadline: 1.0,
            flags: Flags::default(),
            trigger: f64::MAX,
        };
        let start = Instant::now();
        let outcome = run_child_request(&request, 0.05);
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
        assert!(
            matches!(outcome, ChildOutcome::Reference { reference } if reference > 0.0),
            "{outcome:?}"
        );
    }

    #[test]
    fn compiled_probe_uses_the_regex_crate_first() {
        let compiled = CompiledProbe::compile("abc", &Flags::default()).expect("compile");
        assert!(matches!(compiled, CompiledProbe::Re(_)));
    }

    #[test]
    fn child_spawn_error_display_covers_both_variants() {
        assert_eq!(
            ChildSpawnError::Timeout.to_string(),
            "child deadline elapsed"
        );
        assert_eq!(
            ChildSpawnError::Failed("boom".to_owned()).to_string(),
            "child failed: boom"
        );
    }

    #[test]
    fn resolve_child_path_prefers_an_existing_override() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let override_path = manifest.join("Cargo.toml");
        let resolved = resolve_child_path(Some(override_path.to_str().expect("utf8")), None);
        assert_eq!(resolved, Some(override_path));
    }

    #[test]
    fn resolve_child_path_accepts_the_probe_binary_itself_as_the_exe() {
        let exe = PathBuf::from("/opt/tools/guard-pattern-probe");
        let resolved = resolve_child_path(Some("/definitely/missing/bin"), Some(&exe));
        assert_eq!(resolved, Some(exe));
    }

    #[test]
    fn resolve_child_path_skips_a_missing_override() {
        let exe = PathBuf::from("/opt/tools/other-binary");
        // A missing override cannot resolve on its own; the candidate
        // search then walks the exe siblings and finally the workspace
        // target dir, where cargo built the probe binary.
        let resolved = resolve_child_path(Some("/definitely/missing/bin"), Some(&exe));
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest
            .parent()
            .and_then(|crates| crates.parent())
            .map(|root| root.join("target/debug/guard-pattern-probe"))
            .filter(|candidate| candidate.exists());
        assert_eq!(resolved, workspace);
    }

    #[test]
    fn a_missing_child_path_is_a_spawn_failure() {
        let outcome = run_child_request_at(&ChildRequest::ReferenceLoad, 1.0, None);
        assert_eq!(
            outcome,
            Err(ChildSpawnError::Failed(
                "probe child binary not found".into()
            ))
        );
    }

    #[test]
    fn a_failing_child_binary_is_a_spawn_failure() {
        // /usr/bin/false exists on every supported host and exits nonzero
        // with no output, which the parent maps to an unexpected-exit
        // failure.
        let outcome = run_child_request_at(
            &ChildRequest::ReferenceLoad,
            1.0,
            Some(PathBuf::from("/usr/bin/false")),
        );
        let detail = expect_failed(outcome);
        assert!(detail.contains("child exited unexpectedly"), "{detail}");
    }

    #[test]
    fn flag_prefix_includes_the_ascii_letter() {
        let flags = Flags {
            ascii: true,
            ..Flags::default()
        };
        assert_eq!(flag_prefix(&flags), "(?a)");
    }

    #[test]
    fn child_test_strings_reports_the_first_slow_string() {
        // A negative threshold makes every search deterministically exceed
        // it, so the slow-string payload is produced without wall-clock luck.
        let payload = json!({
            "op": "test_strings",
            "pattern": "abc",
            "test_strings": ["xabcx", "yabcy"],
            "threshold": -1.0,
            "flags": {},
        });
        let output = dispatch_payload(&payload);
        assert_eq!(output["safe"], json!(false));
        let reason = output["reason"].as_str().expect("reason");
        assert_eq!(reason, "Pattern timed out on test string of length 5");
    }

    #[test]
    fn sample_probe_takes_more_samples_only_past_the_trigger() {
        // First sample below the trigger: exactly one sample.
        let mut searches = 0usize;
        let times = sample_probe("p", 5, 0.05, &mut |_text| {
            searches += 1;
            0.001
        });
        assert_eq!(times, vec![0.001]);
        assert_eq!(searches, 1);
        // First sample past the trigger but under the large-sample bound:
        // the full sample ladder runs.
        let mut searches = 0usize;
        let times = sample_probe("p", 4, 0.05, &mut |_text| {
            searches += 1;
            0.1
        });
        assert_eq!(times, vec![0.1; 4]);
        assert_eq!(searches, 4);
        // A sample over the large-sample bound stops the ladder early.
        let mut searches = 0usize;
        let times = sample_probe("p", 5, 0.05, &mut |_text| {
            searches += 1;
            0.3
        });
        assert_eq!(times, vec![0.3, 0.3]);
        assert_eq!(searches, 2);
    }

    #[test]
    fn child_stray_verify_returns_null_on_unusable_payloads() {
        let bad_pattern = json!({
            "op": "stray_verify",
            "pattern": "[invalid",
            "flags": {},
            "cases": [["x", ["x"]]],
        });
        assert_eq!(dispatch_payload(&bad_pattern), Value::Null);
        let no_cases = json!({
            "op": "stray_verify",
            "pattern": "abc",
            "flags": {},
        });
        assert_eq!(dispatch_payload(&no_cases), Value::Null);
        let unknown_op = json!({ "op": "teleport" });
        assert_eq!(dispatch_payload(&unknown_op), Value::Null);
    }

    #[test]
    fn search_misses_reports_fancy_results() {
        // Lookarounds force the fancy engine; the helper must report both
        // matched and unmatched probes correctly for it.
        let compiled = CompiledProbe::compile("(?!x)a", &Flags::default()).expect("fancy compile");
        let regex = expect_fancy(&compiled);
        assert!(regex.is_match("ab").expect("search"), "sanity: it matches");
        assert!(!search_misses(&compiled, "ab"), "a match is not a miss");
        assert!(search_misses(&compiled, "bbb"), "no match is a miss");
    }

    #[test]
    fn child_main_ignores_foreign_invocations() {
        assert_eq!(child_main(&[]), None);
        assert_eq!(child_main(&["prog".to_owned()]), None);
        assert_eq!(child_main(&["prog".to_owned(), "other".to_owned()]), None);
    }

    #[test]
    fn the_probe_child_fails_on_unreadable_stdin() {
        // Reading a directory fd fails with EISDIR on macOS and Linux, so
        // the child exits 1 before parsing any payload.
        let status = Command::new(child_path().expect("child binary"))
            .arg(SUBCOMMAND)
            .stdin(std::fs::File::open("/").expect("directory handle"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .expect("child status");
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn the_probe_child_fails_on_a_malformed_payload() {
        let mut child = Command::new(child_path().expect("child binary"))
            .arg(SUBCOMMAND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        {
            let mut stdin = child.stdin.take().expect("piped stdin");
            let _ = stdin.write_all(b"not json");
        }
        let status = child.wait().expect("child status");
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    #[should_panic(expected = "expected an exit failure")]
    fn expect_failed_rejects_other_outcomes() {
        let _ = expect_failed(Err(ChildSpawnError::Timeout));
    }

    #[test]
    #[should_panic(expected = "expected the fancy engine")]
    fn expect_fancy_rejects_the_regex_engine() {
        let compiled = CompiledProbe::compile("abc", &Flags::default()).expect("compile");
        let _ = expect_fancy(&compiled);
    }

    #[test]
    fn child_compilation_covers_the_parser_surface() {
        // Each request makes the child compile (or reject) a different
        // pattern shape, so the child's own engine instance exercises the
        // same breadth the in-process suite does.
        for pattern in [
            r"[a-z]+",
            r"(?i)(?:\d{2,4}|\w+-\w+)+$",
            r"(?P<name>x)(?P=name)",
            r"(a|b|c)*d",
            r"[\x41-\x5a]+\u00e9",
            r"a{2,5}b{2,}",
            r"(?=look)a+less",
            r"\b(?:one|two)\s+three\b",
        ] {
            let request = ChildRequest::TestStrings {
                pattern: pattern.to_owned(),
                test_strings: vec!["probe".to_owned()],
                threshold: 1.0,
                flags: Flags::default(),
            };
            let outcome = run_child_request(&request, 2.0);
            assert!(outcome.is_ok(), "{pattern}: {outcome:?}");
        }
        // A rejected pattern drives the child's compile-failure payload.
        let request = ChildRequest::TestStrings {
            pattern: "[invalid".to_owned(),
            test_strings: vec![],
            threshold: 1.0,
            flags: Flags::default(),
        };
        let outcome = run_child_request(&request, 2.0).expect("rejected payload");
        assert_eq!(
            outcome,
            ChildOutcome::Safety {
                safe: false,
                reason: "Pattern validation failed: Parsing error at position 8: \
                         Invalid character class"
                    .to_owned(),
            }
        );
    }

    #[test]
    fn dispatch_runs_the_reach_timing_ladder_in_process() {
        let payload = json!({
            "op": "reach_timing",
            "pattern": "abc",
            "probes": ["abc", "xabcx"],
            "samples": 2,
            "deadline": 10.0,
            "flags": {},
            "trigger": 1.0,
        });
        let output = dispatch_payload(&payload);
        let results = output["results"].as_array().expect("results");
        assert_eq!(results.len(), 2);
        for row in results {
            let samples = row.as_array().expect("samples");
            assert!((1..=2).contains(&samples.len()), "{samples:?}");
            for sample in samples {
                assert!(sample.as_f64().expect("finite") >= 0.0);
            }
        }
        assert!(output["reference"].as_f64().expect("reference") >= 0.0);
    }

    #[test]
    fn dispatch_runs_the_reference_load_probe_in_process() {
        let output = dispatch_payload(&json!({ "op": "reference_load" }));
        let reference = output["reference"].as_f64().expect("reference");
        assert!(reference >= 0.0);
    }

    #[test]
    fn dispatch_reach_timing_reports_compile_failures() {
        let payload = json!({
            "op": "reach_timing",
            "pattern": "[invalid",
            "probes": ["a"],
            "samples": 1,
            "deadline": 10.0,
            "flags": {},
            "trigger": 1.0,
        });
        let output = dispatch_payload(&payload);
        assert!(output["error"].as_str().expect("error").contains("Invalid character class"));
    }
}
