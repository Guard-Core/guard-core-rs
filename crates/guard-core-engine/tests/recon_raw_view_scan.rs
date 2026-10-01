// The suite's assert-on-emptiness idiom is pervasive here; clippy 1.99's new
// assert_is_empty lint (assert_eq!(x, []) for the failure printout) is allowed
// file-wide rather than rewriting the assertion surface in a release train.
#![allow(unknown_lints)] // the lint name below postdates the 1.92 MSRV clippy
#![allow(clippy::assert_is_empty)]

//! Honesty tests for the recon raw-view scan (upstream guard-core fix on the
//! `fix/raw-view-recon-scan` branch, mirroring
//! `tests/test_sus_patterns/test_recon_raw_view_scan.py`).
//!
//! The configured pipeline's preprocessor folds LDAP hex escapes (`\de` ->
//! `Þ`) before the pattern tables run, so a recon probe such as `\default`
//! arrives mangled on the processed views, and the recon-category rows were
//! excluded from the raw-view pattern set, so the original input was never
//! scanned against them. The raw view now carries the recon rows too: the
//! original value is scanned against them IN ADDITION to the processed
//! views, with the #116 leading-separator gate applied unchanged (bare words
//! stay innocent outside `url_path`/`unknown`) and a (pattern, match)
//! deduplication on merge so a row matching in both views is counted once.
//!
//! Level note: unlike `recon_bare_word_context.rs` (which pins the legacy
//! singleton and therefore scans a raw `scan_view` pass), these tests go
//! through the full `detect()` pipeline, because the whole point is that the
//! pipeline's own preprocessor mangles backslash probes on the processed
//! views and only the signal-preserving raw view still carries them.

use guard_core_engine::detect::{self, DetectConfig, Threat};
use guard_core_engine::patterns::RegexThreat;

const fn corpus_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

fn recon_threats(verdict: &detect::DetectVerdict) -> Vec<&RegexThreat> {
    verdict
        .threats
        .iter()
        .filter_map(|t| match t {
            Threat::Regex(r) if r.category == "recon" => Some(r),
            _ => None,
        })
        .collect()
}

fn detect_recon_matches(value: &str, context: &str) -> Vec<String> {
    let verdict = detect::detect(value, context, &corpus_config());
    recon_threats(&verdict)
        .iter()
        .map(|t| t.match_text.clone())
        .collect()
}

#[test]
fn backslash_probe_in_query_param_detects_through_the_pipeline() {
    // The processed views fold `\de` into `Þ` (`\default` -> `Þfault`), so
    // these fire only through the raw view.
    for probe in ["\\default", "\\report.asp"] {
        assert!(
            !detect_recon_matches(probe, "query_param").is_empty(),
            "backslash probe {probe:?} not detected in query_param"
        );
    }
}

#[test]
fn bare_words_stay_innocent_through_the_pipeline() {
    for word in ["default", "SAP", "actuator", "README.md"] {
        for context in ["query_param", "request_body"] {
            assert!(
                detect_recon_matches(word, context).is_empty(),
                "bare word {word:?} in {context} read as a recon probe"
            );
        }
    }
}

#[test]
fn backslash_probe_as_the_url_path_detects() {
    // The #116 semantics: a backslash-prefixed probe is recon as a URL path
    // value; the raw view must not lose it to the hex decoder.
    assert!(!detect_recon_matches("\\default", "url_path").is_empty());
}

#[test]
fn case_folding_still_applies_on_raw_view_matches() {
    // The rows compile case-insensitively (pattern-row case parity), and the
    // raw view runs the same compiled entries.
    assert!(!detect_recon_matches("\\SAP", "query_param").is_empty());
}

#[test]
fn embedded_json_leaf_context_follows_the_probe_gate() {
    // The `:embedded_json` suffix rides into the validator context, and the
    // gate splits it off: the separator-leading value fires, the bare word
    // does not.
    assert!(!detect_recon_matches("\\default", "request_body:embedded_json").is_empty());
    assert!(detect_recon_matches("default", "request_body:embedded_json").is_empty());
    assert!(!detect_recon_matches("\\default", "query_param:embedded_json").is_empty());
    assert!(detect_recon_matches("default", "query_param:embedded_json").is_empty());
}

#[test]
fn row_matching_both_views_is_counted_once() {
    // `\report.asp` survives preprocessing intact: the processed views and
    // the raw view both match it, and the raw-view merge must not
    // double-count it.
    let verdict = detect::detect("\\report.asp", "query_param", &corpus_config());
    let recon = recon_threats(&verdict);
    assert_eq!(recon.len(), 1, "double-counted raw-view sighting");
    assert_eq!(recon[0].match_text, "\\report.asp");
    assert!(verdict.is_threat);
}

#[test]
fn hex_decoded_separator_probe_still_detects_once() {
    // `\2fdefault` decodes to `/default` on the processed views; the raw
    // view does not match it, and the decoded sighting stays a single recon
    // hit.
    let verdict = detect::detect("\\2fdefault", "query_param", &corpus_config());
    let recon = recon_threats(&verdict);
    assert_eq!(recon.len(), 1);
    assert_eq!(recon[0].match_text, "/default");
}

#[test]
fn slash_backslash_url_path_stays_clean_on_both_views() {
    // `/\default` is not a probe shape on any view: the leading slash
    // already satisfies the path prefix, so the row cannot rematch on
    // `\default`.
    let verdict = detect::detect("/\\default", "url_path", &corpus_config());
    assert!(!verdict.is_threat);
    assert!(verdict.threats.is_empty());
}

#[test]
fn hex_folded_run_stays_clean() {
    // `\de\ad\be\ef` folds to non-ASCII text on the processed views and is
    // not a probe on the raw view either; folding must not create a recon
    // hit.
    let verdict = detect::detect("\\de\\ad\\be\\ef", "query_param", &corpus_config());
    assert!(!verdict.is_threat);
    assert!(verdict.threats.is_empty());
}

#[test]
fn two_row_probe_keeps_the_reference_multiset() {
    // Both separator forms hit the default-page row and the extension row,
    // exactly the threat multiset the reference produces.
    for value in ["/default.asp", "\\default.asp"] {
        let matches = detect_recon_matches(value, "query_param");
        assert_eq!(matches.len(), 2, "multiset drift for {value:?}");
        assert!(
            matches.iter().all(|m| *m == value),
            "match texts drifted for {value:?}: {matches:?}"
        );
    }
}
