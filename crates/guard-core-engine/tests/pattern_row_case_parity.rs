// The suite's assert-on-emptiness idiom is pervasive here; clippy 1.99's new
// assert_is_empty lint (assert_eq!(x, []) for the failure printout) is allowed
// file-wide rather than rewriting the assertion surface in a release train.
#![allow(unknown_lints)] // the lint name below postdates the 1.92 MSRV clippy
#![allow(clippy::assert_is_empty)]

//! Case-sensitivity parity tests for the structural matchers.
//!
//! The reference engine compiles every builtin row with a global
//! `re.IGNORECASE` (`suspatterns_handler.py`, `_BUILTIN_PATTERN_COMPILE_FLAGS`);
//! a row only narrows case via an inline `(?-i:...)` group, and the only rows
//! that do are the four deserialization base64 magic prefixes. The structural
//! matchers must therefore fold ASCII case exactly like those rows, otherwise
//! an uppercase probe (`/SAP`, `/.ENV`, `Thumbs.DB`) is under-detected relative
//! to the reference.
//!
//! Level note: like `recon_bare_word_context.rs`, these pin the raw single-value
//! `scan_view` pass (the legacy handler level), not the enhanced `detect()`
//! pipeline, whose processed view folds backslash escapes on both engines.

use guard_core_engine::detect;
use guard_core_engine::patterns::{self, ViewFilter};

/// Raw single-value scan mirroring the pinned legacy handler (same shape as
/// `recon_bare_word_context.rs`).
fn scan(value: &str, context: &str) -> Vec<(String, String)> {
    let normalized = detect::normalize_context(context);
    let skip_filter = matches!(normalized, "unknown" | "request_body");
    patterns::scan_view(value, ViewFilter::All, normalized, skip_filter, normalized)
        .into_iter()
        .map(|t| (t.category, t.pattern))
        .collect()
}

/// Both case variants of a probe must fire identically: the reference row is
/// case-insensitive, so the uppercase form is under-detection when missed.
/// Probes avoid the recon bare-word gate by leading with `/` where the
/// context is a query or body value.
const CASE_VARIANT_PROBES: &[(&str, &str)] = &[
    // recon id 126 (the reviewed row): sap/ise/nidp/... path words
    ("/sap", "/SAP"),
    // recon id 116: server extension probe (compiled row, sanity anchor)
    ("/default.asp", "/DEFAULT.ASP"),
    // recon id 122: cgi-bin
    ("/cgi-bin/a.cgi", "/CGI-BIN/a.cgi"),
    // recon id 121: recon app words incl. mixed-case literals
    ("/geoserver/web", "/GEOSERVER/web"),
    ("/scadabr/x", "/SCADABR/x"),
    ("/magicinfo/x", "/MAGICINFO/x"),
    // recon id 123: device probes
    ("/hnap1", "/HNAP1"),
    // recon id 124: language(s)
    ("/language", "/LANGUAGE"),
    // recon id 125: repo metadata files
    ("/readme.txt", "/README.TXT"),
    ("/changelog", "/CHANGELOG"),
    // recon id 128: agent config dirs
    ("/.openclaw/config", "/.OPENCLAW/config"),
    // recon id 130: inicio page
    ("/inicio.html", "/INICIO.HTML"),
    // recon id 131: dev tool dirs
    ("/.cursor/config", "/.CURSOR/config"),
    // recon id 132: build files (incl. the .ya?ml suffix branch)
    ("/Dockerfile", "/DOCKERFILE"),
    ("/docker-compose.yml", "/DOCKER-COMPOSE.YML"),
    ("/Jenkinsfile", "/JENKINSFILE"),
    // recon id 133: secret files
    ("/secrets.json", "/SECRETS.JSON"),
    ("/credentials.yml", "/CREDENTIALS.YML"),
    // recon id 134/135: exchange + dns endpoints
    ("/autodiscover/a.xml", "/AUTODISCOVER/a.xml"),
    ("/dns-query", "/DNS-QUERY"),
    // recon id 136: git internals
    ("/.git/HEAD", "/.GIT/HEAD"),
    // sensitive_file id 101: .env
    ("/.env", "/.ENV"),
    ("/.env.local", "/.ENV.LOCAL"),
    // sensitive_file id 103: config.* files
    ("/config.env", "/CONFIG.ENV"),
    ("/config.env", "/config.ENV"),
    // sensitive_file id 104: source maps
    ("/app.map", "/app.MAP"),
    // sensitive_file id 106: vcs dirs
    ("/.git/config", "/.GIT/config"),
    ("/.svn/entries", "/.SVN/entries"),
    // cms_probing id 109: wordpress
    ("/wp-login.php", "/WP-LOGIN.php"),
    ("/wp-admin/setup-config.php", "/WP-ADMIN/setup-config.php"),
    // cms_probing id 111: phpinfo page
    ("/phpinfo.php", "/PHPINFO.PHP"),
    // cms_probing id 113: backup files
    ("/config.php.bak", "/config.php.BAK"),
    ("/index.php.old", "/index.php.OLD"),
    // cms_probing id 114: server metadata files
    ("/.htaccess", "/.HTACCESS"),
    ("/Thumbs.db", "/THUMBS.DB"),
    ("/.DS_Store", "/.DS_STORE"),
    // recon id 117: management endpoints (required-separator row)
    ("/system/credentials", "/system/CREDENTIALS"),
    // recon id 119: actuator
    ("/actuator/env", "/ACTUATOR/env"),
];

#[test]
fn structural_probe_rows_fold_case_like_the_reference() {
    for (lower, upper) in CASE_VARIANT_PROBES {
        for context in ["url_path", "query_param"] {
            let lower_hits = scan(lower, context);
            let upper_hits = scan(upper, context);
            assert!(
                !lower_hits.is_empty(),
                "baseline lowercase probe {lower:?} in {context} does not fire"
            );
            assert!(
                !upper_hits.is_empty(),
                "uppercase probe {upper:?} in {context} is under-detected; \
                 the reference row is case-insensitive (lower fires, upper does not)"
            );
            let lower_cats: Vec<&str> = lower_hits.iter().map(|(c, _)| c.as_str()).collect();
            let upper_cats: Vec<&str> = upper_hits.iter().map(|(c, _)| c.as_str()).collect();
            assert_eq!(
                lower_cats, upper_cats,
                "case variants disagree on categories in {context}"
            );
        }
    }
}

#[test]
fn proto_pollution_assignment_folds_case() {
    // id 139: `Object\.prototype...` with the reference's builtin IGNORECASE
    assert!(!scan("Object.prototype.x = 1", "request_body").is_empty());
    assert!(!scan("object.prototype.x = 1", "request_body").is_empty());
    assert!(!scan("OBJECT.PROTOTYPE.x = 1", "request_body").is_empty());
    // the negative lookahead still holds in every case
    assert!(scan("object.prototype.x == 1", "request_body").is_empty());
}

#[test]
fn file_upload_marker_extensions_fold_case() {
    // ids 90-92: the dangerous extension marker behind the (?![A-Za-z0-9])
    // guard is case-insensitive in the reference
    assert!(!scan(r#"filename="shell.PHP.jpg""#, "request_body").is_empty());
    assert!(!scan(r#"filename="x.PHTML""#, "request_body").is_empty());
    assert!(!scan(r#"filename="a.JSP""#, "request_body").is_empty());
    assert!(scan(r#"filename="report.pdf""#, "request_body").is_empty());
}

#[test]
fn deserialization_magic_prefixes_stay_case_sensitive() {
    // The four `(?-i:...)` rows are the reference's only deliberate
    // case-sensitive rows; Rust must keep matching them exactly.
    for (fires, silent) in [
        (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
            "ro0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        ),
        (
            "AAEAAAD/////AQAAAAAAAAAMAgAA",
            "aaeaaad/////AQAAAAAAAAAMAgAA",
        ),
        (
            "gASVAAAAAAAAACMAAAAAAAAAAw==",
            "gAsVAAAAAAAAACMAAAAAAAAAAw==",
        ),
        ("BAhJGlNpZ25hdHVyZQ==\n", "bahJGlNpZ25hdHVyZQ==\n"),
    ] {
        assert!(
            !scan(fires, "request_body").is_empty(),
            "exact-case magic {fires:?} must fire"
        );
        assert!(
            scan(silent, "request_body").is_empty(),
            "wrong-case magic {silent:?} must not fire (reference (?-i:) row)"
        );
    }
}
