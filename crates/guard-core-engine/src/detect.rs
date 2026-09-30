//! Public detection entry point: the spec 4.0.2 `SusPatternsManager.detect`
//! pipeline (preprocess, four scan views, semantic analysis, scoring).
//!
//! View passes mirror the reference mixins:
//! - processed view (`raw_view_only=False`): excludes raw-view-only and
//!   URL-decoded-view-only patterns;
//! - raw signal-preserving view (`raw_view_only=True`): raw-view-only
//!   patterns plus the recon rows (the processed views fold LDAP hex
//!   escapes such as `\default` before the tables run; duplicates against
//!   the processed view are dropped on merge);
//! - decoded-view path-traversal check (processed vs raw view counts);
//! - URL-decoded view (`url_decoded_view_only=True`): only URL-decoded-view
//!   patterns, content is the precomputed decoded view truncated safely;
//! - decode-budget exhaustion threat when a decode pass hit its budget;
//! - short-base64 additive view (no view exclusion);
//! - semantic analysis over the processed content (skipped for binary-looking
//!   raw content).
//!
//! Scoring follows `_regex_anomaly` / `_calculate_threat_score`: `is_threat`
//! is `sum(regex weights) >= threat_score_threshold or any semantic threat`;
//! `threat_score` is `min(max(regex anomaly, semantic max), 1.0)` when any
//! threat exists, else 0.0.

use crate::patterns::binary;
use crate::patterns::{self, RegexThreat, ViewFilter};
use crate::preprocessor;
use crate::semantic::{self, AnalysisResult, AttackKeywords, AttackStructures};

/// Knob mapping for one detect call (spec `config_knobs`).
#[derive(Debug, Clone, Copy)]
pub struct DetectConfig {
    /// `detection_max_content_length` (semantic budget, truncation budget).
    pub max_content_length: usize,
    /// `detection_max_body_inspect_bytes` (the preprocessor's full-scan cap).
    pub max_full_scan_bytes: usize,
    /// `detection_preserve_attack_patterns`.
    pub preserve_attack_patterns: bool,
    /// `detection_semantic_threshold`.
    pub semantic_threshold: f64,
    /// `detection_threat_score_threshold`.
    pub threat_score_threshold: f64,
    /// `detection_binary_min_run_length` (reference bounds 4..=1024, default
    /// 16): minimum code-point length a printable run inside a binary-dense
    /// multipart file-part payload must reach before the run is handed to the
    /// pattern scan (see [`crate::binary_islands`]).
    pub binary_min_run_length: usize,
}

/// One threat, regex or semantic, exactly as the reference emits it.
#[derive(Debug, Clone, PartialEq)]
pub enum Threat {
    Regex(RegexThreat),
    Semantic(SemanticThreat),
}

/// Semantic threat with the full analysis payload (`_check_semantic_threats`).
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticThreat {
    pub attack_type: String,
    /// `probability` for per-attack-type threats, the overall score for the
    /// `suspicious` fallback (serialized under `threat_score`).
    pub score: f64,
    /// `true` when the score is serialized under the `threat_score` key
    /// (the fallback threat shape).
    pub fallback: bool,
    pub analysis: AnalysisResult,
}

/// Full verdict (`SusPatternsManager.detect` return shape, minus timing).
#[derive(Debug, Clone, PartialEq)]
pub struct DetectVerdict {
    pub is_threat: bool,
    pub threat_score: f64,
    pub threats: Vec<Threat>,
    pub original_length: usize,
    pub processed_length: usize,
}

const KNOWN_CONTEXTS: &[&str] = &[
    "query_param",
    "header",
    "url_path",
    "request_body",
    "unknown",
];
pub const EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX: &str = ":embedded_json";

/// `_normalize_context`: keep the part before the first `:`, map unknown
/// contexts to `unknown`.
#[must_use]
pub fn normalize_context(context: &str) -> &str {
    let head = context.split(':').next().unwrap_or("");
    if KNOWN_CONTEXTS.contains(&head) {
        head
    } else {
        "unknown"
    }
}

fn regex_anomaly(regex_threats: &[RegexThreat]) -> f64 {
    regex_threats.iter().map(|t| t.weight).sum()
}

/// One scan pass with the reference context normalization applied
/// (`_check_regex_patterns` minus the async machinery).
#[must_use]
fn scan_pass(
    view_content: &str,
    filter: ViewFilter,
    normalized_context: &str,
    validator_context: &str,
) -> Vec<RegexThreat> {
    let skip_filter = matches!(normalized_context, "unknown" | "request_body");
    patterns::scan_view(
        view_content,
        filter,
        normalized_context,
        skip_filter,
        validator_context,
    )
}

/// Keep only the scan results whose (pattern, match) pair the earlier views
/// have not already recorded (`_drop_view_duplicate_threats`).
#[must_use]
fn drop_view_duplicate_threats(
    seen_threats: &[RegexThreat],
    new_threats: Vec<RegexThreat>,
) -> Vec<RegexThreat> {
    let mut seen: std::collections::HashSet<(String, String)> = seen_threats
        .iter()
        .map(|threat| (threat.pattern.clone(), threat.match_text.clone()))
        .collect();
    let mut kept = Vec::new();
    for threat in new_threats {
        if seen.insert((threat.pattern.clone(), threat.match_text.clone())) {
            kept.push(threat);
        }
    }
    kept
}

fn semantic_threats(
    processed: &str,
    raw_content: &str,
    config: &DetectConfig,
) -> Vec<SemanticThreat> {
    if binary::looks_like_binary_content(raw_content) {
        return Vec::new();
    }
    let semantic_budget = config.max_content_length;
    let input: String = processed.chars().take(semantic_budget).collect();
    let analysis = semantic::analyze(
        &input,
        &AttackKeywords::default(),
        &AttackStructures::default(),
    );
    let score = semantic::get_threat_score(&analysis);

    let mut threats = Vec::new();
    if score > config.semantic_threshold {
        let mut probs: Vec<(&str, f64)> = analysis
            .attack_probabilities
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        probs.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (attack_type, probability) in probs {
            if probability >= config.semantic_threshold {
                threats.push(SemanticThreat {
                    attack_type: attack_type.to_owned(),
                    score: probability,
                    fallback: false,
                    analysis: analysis.clone(),
                });
            }
        }
        if threats.is_empty() && score >= config.semantic_threshold {
            threats.push(SemanticThreat {
                attack_type: "suspicious".to_owned(),
                score,
                fallback: true,
                analysis,
            });
        }
    }
    threats
}

/// The reference `detect` pipeline over one request content.
#[must_use]
pub fn detect(content: &str, request_context: &str, config: &DetectConfig) -> DetectVerdict {
    let original_length = content.chars().count();
    let (processed, decoded, decode_budget_exhausted) = preprocessor::preprocess_with_decoded(
        content,
        config.max_full_scan_bytes,
        config.preserve_attack_patterns,
        config.max_content_length,
    );
    let processed_length = processed.chars().count();

    let normalized = normalize_context(request_context);
    let validator_context = if request_context.ends_with(EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX) {
        format!("{normalized}{EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}")
    } else {
        normalized.to_owned()
    };

    let mut regex_threats: Vec<RegexThreat> = Vec::new();

    // processed view (raw_view_only = False)
    regex_threats.extend(scan_pass(
        &processed,
        ViewFilter::Processed,
        normalized,
        &validator_context,
    ));

    // raw signal-preserving view (raw_view_only = True)
    let raw_view = preprocessor::preprocess_signal_preserving(
        content,
        config.max_full_scan_bytes,
        config.preserve_attack_patterns,
        config.max_content_length,
    );
    let raw_pass = scan_pass(&raw_view, ViewFilter::Raw, normalized, &validator_context);
    // Threats and matched patterns are parallel lists in the reference (one
    // append per match), so a raw-view sighting of a pattern over text the
    // processed views already matched is the same evidence and must not
    // inflate the threat score (`_drop_view_duplicate_threats`).
    regex_threats.extend(drop_view_duplicate_threats(&regex_threats, raw_pass));

    // decoded-view path traversal (processed vs raw view shape counts)
    if let Some(threat) = patterns::decoded_view_traversal_threat(&processed, &raw_view) {
        regex_threats.push(threat);
    }

    // URL-decoded view (url_decoded_view_only = True): the precomputed decoded
    // view, truncated safely
    let url_decoded_view = preprocessor::truncate_safely(
        &decoded,
        config.max_full_scan_bytes,
        config.preserve_attack_patterns,
        config.max_content_length,
    );
    regex_threats.extend(scan_pass(
        &url_decoded_view,
        ViewFilter::UrlDecoded,
        normalized,
        &validator_context,
    ));

    if decode_budget_exhausted {
        regex_threats.push(patterns::decode_budget_exhausted_threat());
    }

    // short-base64 additive view (no view exclusion)
    let additive_view = preprocessor::short_base64_additive_view(
        content,
        config.max_full_scan_bytes,
        config.preserve_attack_patterns,
        config.max_content_length,
    );
    if !additive_view.is_empty() {
        regex_threats.extend(scan_pass(
            &additive_view,
            ViewFilter::All,
            normalized,
            &validator_context,
        ));
    }

    let semantic = semantic_threats(&processed, content, config);

    let anomaly = regex_anomaly(&regex_threats);
    let is_threat = anomaly >= config.threat_score_threshold || !semantic.is_empty();

    let threat_score = if regex_threats.is_empty() && semantic.is_empty() {
        0.0
    } else {
        let semantic_max = semantic.iter().map(|s| s.score).fold(0.0_f64, f64::max);
        (anomaly.max(semantic_max)).min(1.0)
    };

    let mut threats: Vec<Threat> = regex_threats.into_iter().map(Threat::Regex).collect();
    threats.extend(semantic.into_iter().map(Threat::Semantic));

    DetectVerdict {
        is_threat,
        threat_score,
        threats,
        original_length,
        processed_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_config() -> DetectConfig {
        DetectConfig {
            max_content_length: 10_000,
            max_full_scan_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            binary_min_run_length: 16,
        }
    }

    #[test]
    fn traversal_in_url_path_context() {
        let v = detect("/files?name=../../etc/passwd", "url_path", &corpus_config());
        assert!(v.is_threat);
        assert!((v.threat_score - 1.0).abs() < f64::EPSILON);
        assert_eq!(v.threats.len(), 2);
        assert_eq!(v.original_length, 28);
        assert_eq!(v.processed_length, 28);
    }

    #[test]
    fn benign_content_is_clean() {
        let v = detect("hello world", "request_body", &corpus_config());
        assert!(!v.is_threat);
        assert!((v.threat_score - 0.0).abs() < f64::EPSILON);
        assert!(v.threats.is_empty());
    }

    #[test]
    fn context_filtering_gates_sqli_narrow() {
        // `\w/\*(?!!)[^*]*\*/\w` is SQLI_NARROW (no url_path/header)
        let hit = detect("a/**/b", "request_body", &corpus_config());
        assert!(
            hit.threats
                .iter()
                .any(|t| matches!(t, Threat::Regex(r) if r.category == "sqli"))
        );
        // a url_path verdict carrying other threats has no sqli comment hit
        let miss = detect("/files?name=../../etc/passwd", "url_path", &corpus_config());
        assert!(
            miss.threats
                .iter()
                .any(|t| matches!(t, Threat::Regex(r) if r.category == "dir_traversal"))
        );
        assert!(!miss.threats.iter().any(
            |t| matches!(t, Threat::Regex(r) if r.category == "sqli" && r.pattern.contains("/\\*"))
        ));
    }

    #[test]
    fn unknown_context_normalizes() {
        assert_eq!(normalize_context("weird:thing"), "unknown");
        assert_eq!(
            normalize_context("query_param:embedded_json"),
            "query_param"
        );
        assert_eq!(normalize_context("header"), "header");
    }

    #[test]
    fn raw_view_only_patterns_need_the_raw_view() {
        // encoded-dot traversal only fires on the raw view
        let v = detect("/search?q=%2e%2e%2f", "url_path", &corpus_config());
        assert!(
            v.threats
                .iter()
                .any(|t| matches!(t, Threat::Regex(r) if r.category == "path_traversal"))
        );
    }

    #[test]
    fn regex_anomaly_sums_weights() {
        // two 0.5-weight sqli hits cross the 1.0 threshold together
        let v = detect("SELECT * FROM users", "request_body", &corpus_config());
        assert!(v.is_threat);
        // a semantic threat rides along on its own (no regex hits of its
        // own weight change): it contributes nothing to the anomaly sum
        let semantic_side = detect(&mixed_content(), "request_body", &corpus_config());
        let semantic_threat = semantic_side
            .threats
            .iter()
            .find(|t| matches!(t, Threat::Semantic(_)))
            .expect("the mixed payload carries a semantic threat");
        let anomaly: f64 = v
            .threats
            .iter()
            .chain(std::iter::once(semantic_threat))
            .filter_map(|t| match t {
                Threat::Regex(r) => Some(r.weight),
                Threat::Semantic(_) => None,
            })
            .sum();
        assert!((anomaly - 1.0).abs() < 1e-9, "anomaly {anomaly}");

        // a mixed verdict: semantic threats carry no anomaly weight
        let mixed = detect(&mixed_content(), "request_body", &corpus_config());
        assert!(
            mixed
                .threats
                .iter()
                .any(|t| matches!(t, Threat::Semantic(_)))
        );
        let mixed_anomaly: f64 = mixed
            .threats
            .iter()
            .filter_map(|t| match t {
                Threat::Regex(r) => Some(r.weight),
                Threat::Semantic(_) => None,
            })
            .sum();
        assert!(mixed_anomaly > 0.0, "regex hits still carry weight");
        assert!(mixed.is_threat);
    }

    fn mixed_content() -> String {
        format!(
            "select union insert update delete drop from where order group having concat \
             substring database table column (1 OR 1=1) {}",
            "A".repeat(120)
        )
    }

    #[test]
    fn an_embedded_json_leaf_context_keeps_its_suffix() {
        // a context carrying the embedded-json suffix keeps it through
        // normalization for the validator seam
        let v = detect(
            "SELECT * FROM users",
            "request_body:embedded_json",
            &corpus_config(),
        );
        assert!(v.is_threat);
    }

    #[test]
    fn a_short_base64_view_scans_as_an_additive_pass() {
        // `JHt9` decodes to `${}`: the short-token additive view fills and
        // its fragments run through their own scan pass, surfacing the
        // command-injection shape the raw text hides
        let v = detect("JHt9", "request_body", &corpus_config());
        assert!(v.is_threat, "unexpected verdict: {v:?}");
        assert!(
            v.threats
                .iter()
                .any(|t| matches!(t, Threat::Regex(r) if r.category == "cmd_injection")),
            "verdict: {v:?}"
        );
    }

    #[test]
    fn binary_raw_content_never_yields_semantic_threats() {
        // a NUL-heavy raw payload trips the binary gate before any scan
        let processed = "\0".repeat(16);
        assert!(
            semantic_threats(&processed, &processed, &corpus_config()).is_empty(),
            "binary content is exempt from the semantic pass"
        );
    }

    #[test]
    fn an_exhausted_decode_budget_appends_its_marker_threat() {
        // `%25` followed by fifteen `25` pairs peels exactly one encoding
        // layer per pass, so the 16-iteration decode budget runs out and
        // the synthetic exhaustion threat rides on the verdict
        let content = format!("%25{}", "25".repeat(15));
        let v = detect(&content, "url_path", &corpus_config());
        assert!(
            v.threats.iter().any(|t| matches!(
                t,
                Threat::Regex(r) if r.pattern == "decode_budget_exhausted"
            )),
            "verdict: {v:?}"
        );
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    fn corpus_config() -> DetectConfig {
        DetectConfig {
            max_content_length: 10_000,
            max_full_scan_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            binary_min_run_length: 16,
        }
    }

    #[test]
    fn a_semantic_fallback_threat_reports_suspicious() {
        // high aggregate score without any single attack class above the
        // threshold: the fallback "suspicious" semantic threat fires
        let mut content = String::from("from where drop select ");
        content.push_str(&"A".repeat(120));
        content.push_str(" ({}$x==) foo(");
        let v = detect(&content, "request_body", &corpus_config());
        assert!(v.is_threat, "verdict: {v:?}");
        assert!(
            v.threats.iter().any(
                |t| matches!(t, Threat::Semantic(s) if s.attack_type == "suspicious" && s.fallback)
            ),
            "verdict: {v:?}"
        );
    }

    #[test]
    fn a_mixed_verdict_scores_the_semantic_maximum_against_the_anomaly() {
        // regex sqli hits plus a semantic sql threat: the threat score folds
        // over both lists
        let content = format!(
            "select union insert update delete drop from where order group having concat \
             substring database table column (1 OR 1=1) {}",
            "A".repeat(120)
        );
        let v = detect(&content, "request_body", &corpus_config());
        assert!(v.is_threat);
        assert!(
            v.threats
                .iter()
                .any(|t| matches!(t, Threat::Regex(r) if r.category == "sqli"))
        );
        assert!(v.threats.iter().any(|t| matches!(t, Threat::Semantic(_))));
        let semantic_max = v
            .threats
            .iter()
            .filter_map(|t| match t {
                Threat::Semantic(s) => Some(s.score),
                Threat::Regex(_) => None,
            })
            .fold(0.0_f64, f64::max);
        let anomaly = v
            .threats
            .iter()
            .filter_map(|t| match t {
                Threat::Regex(r) => Some(r.weight),
                Threat::Semantic(_) => None,
            })
            .sum::<f64>();
        assert!((v.threat_score - anomaly.max(semantic_max).min(1.0)).abs() < 1e-9);
    }
}
