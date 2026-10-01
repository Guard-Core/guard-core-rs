// The suite's assert-on-emptiness idiom is pervasive here; clippy 1.99's new
// assert_is_empty lint (assert_eq!(x, []) for the failure printout) is allowed
// file-wide rather than rewriting the assertion surface in a release train.
#![allow(unknown_lints)] // the lint name below postdates the 1.92 MSRV clippy
#![allow(clippy::assert_is_empty)]

//! Honesty tests for the recon leading-separator gate (upstream guard-core
//! #115, fix PR #116, commit `08f79d67`, ported from
//! `tests/test_sus_patterns/test_recon_bare_word_context.py`).
//!
//! The whole-value recon rows whose leading path separator is optional read a
//! bare query or body value such as `?system=SAP` or `README.md` as a probe
//! path, so the request was flagged and the hit counted toward auto-ban.
//! Outside `url_path`/`unknown` a hit from those rows is only a probe when
//! the matched value starts with `/` or `\`; the gated rows are derived from
//! the table (recon category plus the anchor), not hand-listed, and other
//! families that also carry the anchor (`cms_probing`, `sensitive_file`) are
//! deliberately not gated.
//!
//! Level note: the upstream test pins the legacy detection singleton, so it
//! scans the raw value with the full table. The mirror here is therefore a
//! raw `scan_view` pass, not the enhanced `detect()` pipeline, whose
//! processed view applies the same LDAP hex-escape decode upstream and here
//! (backslash-leading probes are folded before the table runs on both sides).

use guard_core_engine::detect::{self, EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX};
use guard_core_engine::patterns::{self, ViewFilter, table};

/// Ordinary field values that the whole-value recon rows match when the
/// leading "/" is optional: product names, enum values, file names.
const BARE_WORDS: &[&str] = &[
    "default",
    "SAP",
    "ise",
    "language",
    "autodiscover",
    "confluence",
    "actuator",
    "cgi-bin",
    "lms/db",
    "README.md",
    "CHANGELOG",
    "Makefile",
    "credentials.json",
    "report.asp",
];

/// Probe paths must keep firing wherever they appear.
const PROBE_PATHS: &[&str] = &[
    "/default.asp",
    "/sap",
    "\\default",
    "\\README.md",
    "/actuator/health",
    "/cgi-bin/test.cgi",
];

/// Value contexts the gate distinguishes; the embedded-JSON leaf form keeps
/// the `:embedded_json` suffix into the gate (validator context).
const VALUE_CONTEXTS: &[&str] = &["query_param", "request_body", "query_param:embedded_json"];

/// Raw single-value scan mirroring the pinned legacy handler: no view
/// exclusion, the same context filter and validator context as the reference.
fn scan(value: &str, context: &str) -> Vec<(String, String)> {
    let normalized = detect::normalize_context(context);
    let validator_context = if context.ends_with(EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX) {
        format!("{normalized}{EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}")
    } else {
        normalized.to_owned()
    };
    let skip_filter = matches!(normalized, "unknown" | "request_body");
    patterns::scan_view(
        value,
        ViewFilter::All,
        normalized,
        skip_filter,
        &validator_context,
    )
    .into_iter()
    .map(|t| (t.category, t.pattern))
    .collect()
}

fn recon_patterns(value: &str, context: &str) -> Vec<String> {
    scan(value, context)
        .into_iter()
        .filter(|(category, _)| category == "recon")
        .map(|(_, pattern)| pattern)
        .collect()
}

fn source_of(id: usize) -> &'static str {
    table::PATTERN_DEFINITIONS
        .iter()
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("table entry {id} exists"))
        .source
}

#[test]
fn bare_word_query_or_body_value_is_not_a_recon_probe() {
    for word in BARE_WORDS {
        for context in VALUE_CONTEXTS {
            let hits = scan(word, context);
            assert!(
                recon_patterns(word, context).is_empty(),
                "bare word {word:?} in {context} read as a recon probe"
            );
            assert!(
                hits.is_empty(),
                "bare word {word:?} in {context} flagged at all: {hits:?}"
            );
        }
    }
}

#[test]
fn probe_path_as_a_query_or_body_value_is_still_recon() {
    for probe in PROBE_PATHS {
        for context in VALUE_CONTEXTS {
            assert!(
                !recon_patterns(probe, context).is_empty(),
                "probe path {probe:?} in {context} no longer recon"
            );
        }
    }
}

#[test]
fn bare_word_as_the_url_path_is_still_recon() {
    for word in ["default", "sap", "README.md", "actuator"] {
        let path = format!("/{word}");
        assert!(
            !recon_patterns(&path, "url_path").is_empty(),
            "bare word {word:?} as the url path no longer recon"
        );
    }
}

#[test]
fn gate_splits_the_validator_context_suffix() {
    // The `:embedded_json` suffix must not leak into the context comparison:
    // the base context decides, so the bare word is rejected while the
    // separator-leading value fires in the very same context string.
    assert!(recon_patterns("sap", "query_param:embedded_json").is_empty());
    assert!(!recon_patterns("/sap", "query_param:embedded_json").is_empty());
}

#[test]
fn gate_sits_between_validator_and_noise_gates() {
    // Direct engine-level check on one gated row (id 124, language(s)):
    // rejected on a bare query value, accepted in url_path even without a
    // leading separator, and the pattern source is in the derived set.
    let entry = patterns::COMPILED_TABLE
        .iter()
        .find(|e| e.entry.id == 124)
        .expect("table entry 124 exists");
    assert!(table::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES.contains(entry.entry.source));
    assert!(
        patterns::find_first_threat(entry, "language", "query_param", None).is_none(),
        "bare query value gated"
    );
    assert!(patterns::find_first_threat(entry, "language", "url_path", None).is_some());
    assert!(patterns::find_first_threat(entry, "/language", "query_param", None).is_some());
}

#[test]
fn derived_set_is_non_empty_and_recon_only() {
    let set = &table::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES;
    assert!(!set.is_empty(), "derivation found no recon rows");
    let anchor = r"\A[/\\]?";
    for source in set.iter() {
        let entry = table::PATTERN_DEFINITIONS
            .iter()
            .find(|e| e.source == *source)
            .expect("set member comes from the table");
        assert_eq!(entry.category, "recon", "non-recon row gated: {source}");
        assert!(
            source.starts_with(anchor),
            "gated row lacks the optional-separator anchor: {source}"
        );
    }
}

#[test]
fn derived_set_covers_the_whole_value_recon_rows() {
    let set = &table::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES;
    // Every recon row built on the optional-separator anchor (ids 116, 119,
    // 121-126, 128-136) must be in the set: 17 rows.
    let expected: Vec<&str> = [
        116_usize, 119, 121, 122, 123, 124, 125, 126, 128, 129, 130, 131, 132, 133, 134, 135, 136,
    ]
    .iter()
    .map(|id| source_of(*id))
    .collect();
    assert_eq!(
        set.len(),
        expected.len(),
        "set matches the table derivation"
    );
    for source in expected {
        assert!(set.contains(source), "recon row missing from the set");
    }
}

#[test]
fn derived_set_excludes_non_recon_anchor_rows() {
    let set = &table::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES;
    // Other families carry the same anchor but are deliberately not gated
    // (reference scoping): sensitive_file ids 101/103/104/105/106/108 and
    // cms_probing ids 109/111/113/114.
    for id in [101_usize, 103, 104, 105, 106, 108, 109, 111, 113, 114] {
        let source = source_of(id);
        assert!(
            !set.contains(source),
            "non-recon anchor row leaked into the set: id {id}"
        );
        assert!(
            source.starts_with(r"\A[/\\]?"),
            "sanity: id {id} has the anchor"
        );
    }
    // Recon rows WITHOUT the optional anchor stay out too: required-separator
    // rows (ids 117/118) and anchor-free rows (ids 120/127).
    for id in [117_usize, 118, 120, 127] {
        assert!(
            !set.contains(source_of(id)),
            "recon row without the anchor leaked into the set: id {id}"
        );
    }
}
