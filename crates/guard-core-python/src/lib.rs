// PyO3 #[pyfunction] docstrings become Python __doc__. They are written in
// numpy style (Parameters/Returns/Raises sections), which trips clippy's
// doc_markdown lint on bare identifiers. The lint targets rustdoc, not Python
// hover text, so silence it crate-wide.
#![allow(clippy::doc_markdown)]

use guard_core_engine::preprocessor;
use guard_core_engine::semantic;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::types::PyList;

/// Preprocess content: unicode normalization, URL/HTML decode, null byte
/// removal, whitespace collapsing, attack-preserving truncation.
///
/// Parameters
/// ----------
/// content : str
///     Raw input to preprocess.
/// max_length : int, optional
///     Maximum output length (default 10000).
/// preserve_attacks : bool, optional
///     Whether to prioritize attack regions when truncating (default True).
///
/// Returns
/// -------
/// str
///     Preprocessed content.
#[pyfunction]
#[pyo3(signature = (content, max_length=10_000, preserve_attacks=true))]
fn preprocess(content: &str, max_length: usize, preserve_attacks: bool) -> String {
    preprocessor::preprocess(content, max_length, preserve_attacks)
}

/// Normalize unicode content (NFKC + lookalike replacement).
///
/// Parameters
/// ----------
/// content : str
///     Raw input.
///
/// Returns
/// -------
/// str
///     Normalized content.
#[pyfunction]
fn normalize_unicode(content: &str) -> String {
    preprocessor::normalize_unicode(content)
}

/// Decode URL-encoded and HTML-escaped content (up to 3 iterations).
///
/// Parameters
/// ----------
/// content : str
///     Encoded input.
///
/// Returns
/// -------
/// str
///     Decoded content.
#[pyfunction]
fn decode_common_encodings(content: &str) -> String {
    preprocessor::decode_common_encodings(content)
}

/// Run full semantic analysis on content.
///
/// Parameters
/// ----------
/// content : str
///     Content to analyze (should be preprocessed first).
///
/// Returns
/// -------
/// dict
///     Analysis results with keys: attack_probabilities, entropy,
///     encoding_layers, is_obfuscated, suspicious_patterns,
///     code_injection_risk, token_count. Each suspicious_patterns entry
///     carries `position` as a Unicode code-point index into `content`
///     (Python str index space), matching the guard-core reference.
#[pyfunction]
fn analyze(py: Python<'_>, content: &str) -> PyResult<Py<PyDict>> {
    let keywords = semantic::AttackKeywords::default();
    let structures = semantic::AttackStructures::default();
    let result = semantic::analyze(content, &keywords, &structures);

    let dict = PyDict::new(py);

    let probs = PyDict::new(py);
    for (k, v) in &result.attack_probabilities {
        probs.set_item(k, v)?;
    }

    dict.set_item("attack_probabilities", probs)?;
    dict.set_item("entropy", result.entropy)?;
    dict.set_item("encoding_layers", result.encoding_layers)?;
    dict.set_item("is_obfuscated", result.is_obfuscated)?;
    dict.set_item("code_injection_risk", result.code_injection_risk)?;
    dict.set_item("token_count", result.token_count)?;

    let patterns = PyList::empty(py);

    for p in &result.suspicious_patterns {
        let d = PyDict::new(py);
        d.set_item("type", p.pattern_type)?;
        d.set_item("pattern", &p.matched)?;
        d.set_item("position", p.position)?;
        d.set_item("context", &p.context)?;
        patterns.append(d)?;
    }

    dict.set_item("suspicious_patterns", patterns)?;

    Ok(dict.into())
}

/// Calculate threat score from analysis results.
///
/// Parameters
/// ----------
/// content : str
///     Content to score (runs full analysis internally).
///
/// Returns
/// -------
/// float
///     Threat score between 0.0 and 1.0.
#[pyfunction]
fn get_threat_score(content: &str) -> f64 {
    let keywords = semantic::AttackKeywords::default();
    let structures = semantic::AttackStructures::default();
    let result = semantic::analyze(content, &keywords, &structures);
    semantic::get_threat_score(&result)
}

/// Calculate Shannon entropy of content.
///
/// Parameters
/// ----------
/// content : str
///     Input text.
///
/// Returns
/// -------
/// float
///     Entropy value in bits.
#[pyfunction]
fn calculate_entropy(content: &str) -> f64 {
    semantic::calculate_entropy(content)
}

/// Detect number of encoding layers in content.
///
/// Parameters
/// ----------
/// content : str
///     Input text.
///
/// Returns
/// -------
/// int
///     Number of detected encoding layers (URL, base64, hex, unicode, HTML).
#[pyfunction]
fn detect_encoding_layers(content: &str) -> u32 {
    semantic::detect_encoding_layers(content)
}

/// Detect if content appears obfuscated.
///
/// Parameters
/// ----------
/// content : str
///     Input text.
///
/// Returns
/// -------
/// bool
///     True if content shows signs of obfuscation.
#[pyfunction]
fn detect_obfuscation(content: &str) -> bool {
    semantic::detect_obfuscation(content)
}

/// Validate if a regex pattern is safe from catastrophic backtracking.
///
/// Parameters
/// ----------
/// pattern : str
///     Regex pattern to validate.
///
/// Returns
/// -------
/// tuple[bool, str]
///     (is_safe, reason) pair.
#[pyfunction]
fn validate_pattern_safety(pattern: &str) -> (bool, String) {
    guard_core_engine::compiler::validate_pattern_safety(pattern)
}

/// Process a batch of contents and return threat scores.
///
/// Single FFI crossing for the entire batch, amortizing PyO3 overhead.
///
/// Parameters
/// ----------
/// contents : list[str]
///     List of raw inputs to process.
/// max_length : int, optional
///     Maximum preprocessed length per item (default 10000).
///
/// Returns
/// -------
/// list[float]
///     Threat scores between 0.0 and 1.0 for each input.
#[pyfunction]
#[pyo3(signature = (contents, max_length=10_000))]
#[allow(clippy::needless_pass_by_value)] // PyO3 boundary: owned Vec required by the extractor; body only reads
fn batch_threat_scores(py: Python<'_>, contents: Vec<String>, max_length: usize) -> Vec<f64> {
    // release GIL during batch,
    // pure Rust work, no Python state touched
    py.detach(|| {
        let keywords = semantic::AttackKeywords::default();
        let structures = semantic::AttackStructures::default();

        contents
            .iter()
            .map(|content| {
                let preprocessed = preprocessor::preprocess(content.as_str(), max_length, true);
                let result = semantic::analyze(&preprocessed, &keywords, &structures);
                semantic::get_threat_score(&result)
            })
            .collect()
    })
}

/// Run the full spec detection pipeline (`detect`) on one request content.
///
/// Parameters
/// ----------
/// content : str
///     Raw request content to scan.
/// request_context : str
///     Detection context (`query_param`, `header`, `url_path`,
///     `request_body`, `unknown`).
/// max_content_length : int, optional
///     `detection_max_content_length` (default 10000).
/// max_full_scan_bytes : int, optional
///     `detection_max_body_inspect_bytes` (default 262144).
/// preserve_attack_patterns : bool, optional
///     `detection_preserve_attack_patterns` (default True).
/// semantic_threshold : float, optional
///     `detection_semantic_threshold` (default 0.7).
/// threat_score_threshold : float, optional
///     `detection_threat_score_threshold` (default 1.0).
/// binary_min_run_length : int, optional
///     `detection_binary_min_run_length` (default 16).
///
/// Returns
/// -------
/// dict
///     Detect verdict with keys: is_threat, threat_score, threats,
///     original_length, processed_length. Threat positions are Unicode
///     code-point indices into the scanned view (Python str index space).
#[pyfunction]
#[pyo3(signature = (content, request_context, max_content_length=10_000, max_full_scan_bytes=262_144, preserve_attack_patterns=true, semantic_threshold=0.7, threat_score_threshold=1.0, binary_min_run_length=16))]
#[allow(clippy::too_many_arguments)] // PyO3 boundary: one argument per spec knob
fn detect_verdict(
    py: Python<'_>,
    content: &str,
    request_context: &str,
    max_content_length: usize,
    max_full_scan_bytes: usize,
    preserve_attack_patterns: bool,
    semantic_threshold: f64,
    threat_score_threshold: f64,
    binary_min_run_length: usize,
) -> PyResult<Py<PyDict>> {
    let config = guard_core_engine::detect::DetectConfig {
        max_content_length,
        max_full_scan_bytes,
        preserve_attack_patterns,
        semantic_threshold,
        threat_score_threshold,
        binary_min_run_length,
    };
    let verdict = guard_core_engine::detect::detect(content, request_context, &config);

    let dict = PyDict::new(py);
    dict.set_item("is_threat", verdict.is_threat)?;
    dict.set_item("threat_score", verdict.threat_score)?;
    dict.set_item("original_length", verdict.original_length)?;
    dict.set_item("processed_length", verdict.processed_length)?;

    let threats = PyList::empty(py);
    for threat in &verdict.threats {
        let entry = PyDict::new(py);
        match threat {
            guard_core_engine::detect::Threat::Regex(r) => {
                entry.set_item("type", "regex")?;
                entry.set_item("pattern", &r.pattern)?;
                entry.set_item("match", &r.match_text)?;
                entry.set_item("position", r.position)?;
                entry.set_item("category", &r.category)?;
                entry.set_item("weight", r.weight)?;
            }
            guard_core_engine::detect::Threat::Semantic(sm) => {
                entry.set_item("type", "semantic")?;
                entry.set_item("attack_type", &sm.attack_type)?;
                entry.set_item("score", sm.score)?;
            }
        }
        threats.append(entry)?;
    }
    dict.set_item("threats", threats)?;

    Ok(dict.into())
}

#[pymodule]
fn guard_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_unicode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_common_encodings, m)?)?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(get_threat_score, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(detect_encoding_layers, m)?)?;
    m.add_function(wrap_pyfunction!(detect_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(validate_pattern_safety, m)?)?;
    m.add_function(wrap_pyfunction!(batch_threat_scores, m)?)?;
    m.add_function(wrap_pyfunction!(detect_verdict, m)?)?;
    Ok(())
}
