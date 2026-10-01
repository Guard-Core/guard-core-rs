//! Detection wiring for the compiled pattern table and its dispatch.
//!
//! Compiles the canonical pattern table and dispatches each pattern to the
//! same structural matcher, windowed finder, candidate validator and
//! scan-window bounds as the guard-core spec 4.0.2 reference
//! (`guard_core/handlers/_suspatterns_regex.py`).
//!
//! Residual patterns (lookaround / backreference constructs the `regex`
//! crate rejects) are served by structural equivalents in `matchers.rs`.
//! Table entry `id` is the table position (see `table.rs`) and keys the
//! dispatch below.

pub mod binary;
pub mod chars_util;
pub mod file_upload;
pub mod ldap_ipv4;
pub mod matchers;
pub mod pickle;
pub mod pyregex;
pub mod scan_window;
pub mod shell_validators;
pub mod table;
pub mod templates;
pub mod xml_xxe;

use std::sync::LazyLock;

use pyregex::{Candidate, PyRegex};

/// A regex threat exactly as the reference `_build_regex_threat` emits it.
#[derive(Debug, Clone, PartialEq)]
pub struct RegexThreat {
    pub pattern: String,
    pub match_text: String,
    /// Unicode code-point index into the scanned view content.
    pub position: usize,
    pub category: String,
    pub weight: f64,
}

pub struct CompiledEntry {
    pub entry: table::TableEntry,
    pub re: Option<PyRegex>,
}

fn rewrite_for_crate(source: &str) -> String {
    // `\A(?:(?!\n).)*` is exactly `[^\n]*` under Python semantics (`.` never
    // matches `\n` without DOTALL), so the negative-lookahead loop rewrites
    // to a plain negated class for the crate.
    source.replace(r"\A(?:(?!\n).)*", r"\A[^\n]*")
}

/// Table ids served by structural matchers or bespoke finders; their
/// canonical sources do not need to compile for the `regex` crate.
const STRUCTURAL_IDS: &[usize] = &[
    3, 9, 12, 21, 27, 33, 42, 45, 62, 63, 64, 75, 78, 79, 90, 91, 92, 98, 99, 101, 102, 103, 104,
    106, 107, 109, 110, 111, 112, 113, 114, 115, 117, 119, 121, 122, 123, 124, 125, 126, 128, 130,
    131, 132, 133, 134, 135, 136, 139, 144, 145, 146, 147,
];

fn is_structural(id: usize) -> bool {
    STRUCTURAL_IDS.contains(&id)
}

pub static COMPILED_TABLE: LazyLock<Vec<CompiledEntry>> = LazyLock::new(|| {
    table::PATTERN_DEFINITIONS
        .iter()
        .map(|entry| {
            let ignore_case = !entry.source.contains("(?-i:");
            let re = PyRegex::compile(&rewrite_for_crate(entry.source), ignore_case)
                .map_err(|e| format!("pattern id {}: {e}", entry.id))
                .ok();
            assert!(
                re.is_some() || is_structural(entry.id),
                "pattern id {} has neither a compiled regex nor a structural matcher",
                entry.id
            );
            CompiledEntry {
                entry: table::TableEntry {
                    id: entry.id,
                    source: entry.source,
                    contexts: entry.contexts,
                    category: entry.category,
                },
                re,
            }
        })
        .collect()
});

pub fn resolve_pattern_weight(pattern_source: &str) -> f64 {
    table::DETECTION_PATTERN_WEIGHT_OVERRIDES
        .get(pattern_source)
        .copied()
        .unwrap_or(1.0)
}

/// Candidate rejection decision: `true` accepts the candidate as a threat
/// (`_CANDIDATE_REJECTION_VALIDATORS`).
#[must_use]
fn candidate_accepts(
    entry: &CompiledEntry,
    haystack: &str,
    candidate: Candidate,
    context: &str,
) -> bool {
    let id = entry.entry.id;
    let text = candidate.text(haystack);
    match id {
        42 => shell_validators::glued_backtick_pair_is_injection(haystack, candidate, context),
        43 => shell_validators::dollar_substitution_pair_is_injection(haystack, candidate, context),
        58 => shell_validators::brace_expansion_is_dangerous_command(text),
        59 => shell_validators::quote_splice_token_is_dangerous_command(text),
        60 => {
            shell_validators::glob_wildcard_token_is_dangerous_command(haystack, candidate, context)
        }
        66 | 67 | 69 => {
            let Some(compiled) = entry.re.as_ref() else {
                return true;
            };
            ldap_ipv4::ldap_wildcard_chain_is_injection(compiled, haystack, &candidate)
        }
        68 => {
            let Some(compiled) = entry.re.as_ref() else {
                return true;
            };
            ldap_ipv4::ldap_paren_conjunction_is_injection(compiled, haystack, &candidate)
        }
        105 => ldap_ipv4::source_extension_path_is_probe(context),
        79 => ldap_ipv4::legacy_ipv4_match_is_blocked(text),
        152 => {
            // group one (`c<module>\n<ident>\n`) ends after the second newline
            let group_one_end = candidate.start
                + haystack[candidate.start..]
                    .find('\n')
                    .and_then(|rel| {
                        let after_first = candidate.start + rel + 1;
                        haystack[after_first..]
                            .find('\n')
                            .map(|r2| after_first + r2 + 1)
                    })
                    .unwrap_or(candidate.end);
            pickle::pickle_global_candidate_is_injection(haystack, candidate, group_one_end)
        }
        _ => true,
    }
}

/// The two XML patterns served by bespoke finders inside the scan-window
/// route, and the generic bounded scan windows (`_SCAN_WINDOW_BOUND_SOURCES`).
fn scan_window_candidates(entry: &CompiledEntry, haystack: &str) -> Option<Vec<Candidate>> {
    let compiled = entry.re.as_ref()?;
    let id = entry.entry.id;
    let (prefix_src, terminator_src) = match id {
        0 => ("<script", r"<\/script\s*>"),
        5 => (r"<[A-Za-z/][^<>]*style\s*=", r"\)"),
        6 => ("<object", r"<\/object\s*>"),
        7 => ("<embed", r"<\/embed\s*>"),
        8 => ("<applet", r"<\/applet\s*>"),
        37 => (r"\.\.;", r"[/\\]"),
        76 => ("<!\\[CDATA\\[", "\\]\\]>"),
        _ => return None,
    };
    #[cfg(not(coverage))] // unreachable: both literals are statically valid
    let prefix = PyRegex::compile(prefix_src, true).ok()?;
    #[cfg(coverage)]
    let prefix = PyRegex::compile(prefix_src, true).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: both literals are statically valid
    let terminator = PyRegex::compile(terminator_src, true).ok()?;
    #[cfg(coverage)]
    let terminator = PyRegex::compile(terminator_src, true).expect("statically valid literal");
    Some(scan_window::bounded_finditer(
        haystack,
        compiled,
        &prefix,
        &terminator,
    ))
}

/// Candidates for one table entry under the reference dispatch order:
/// windowed finder, dedicated scan matcher, bounded scan windows, structural
/// matchers, then plain full-content search.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "pattern dispatch mirrors the reference table order; splitting would obscure the 1:1 mapping"
)]
fn pattern_candidates(entry: &CompiledEntry, haystack: &str) -> Vec<Candidate> {
    let id = entry.entry.id;
    let source = entry.entry.source;
    if let Some(candidates) = scan_window_candidates(entry, haystack) {
        return candidates;
    }
    match id {
        74 => return xml_xxe::xml_system_finditer(haystack),
        77 => return xml_xxe::xml_internal_entity_finditer(haystack),
        75 => return xml_xxe::xml_xxe_public_external_dtd_finditer(haystack),
        3 => return matchers::xss_event_handler_finditer(haystack),
        9 => return matchers::sqli_select_from_finditer(haystack),
        12 => return matchers::sqli_tautology_finditer(haystack),
        21 => return matchers::sqli_inline_comment_finditer(haystack),
        27 => return matchers::sqli_order_by_terminator_finditer(haystack),
        42 => return matchers::glued_backtick_candidate_finditer(haystack),
        45 => return matchers::shell_dash_flag_finditer(haystack),
        62 => return matchers::file_inclusion_bare_host_finditer(haystack),
        63 => return matchers::file_inclusion_scheme_path_finditer(haystack),
        64 => return matchers::file_inclusion_template_url_finditer(haystack),
        103 => return matchers::sensitive_path_config(haystack),
        78 => return matchers::ssrf_private_host_finditer(haystack),
        79 => return matchers::ssrf_numeric_host_finditer(haystack),
        101 => return matchers::sensitive_path_env(haystack),
        104 => {
            return matchers::sensitive_path_scan_ext(haystack, &["map"]);
        }
        106 => {
            return matchers::sensitive_path_dot_alt(haystack, &["git", "svn", "hg", "bzr"]);
        }
        109 => return matchers::sensitive_path_wp_admin(haystack),
        111 => {
            return matchers::sensitive_path_literal_ext(
                haystack,
                &["phpinfo", "info", "test", "php_info"],
                "php",
            );
        }
        113 => {
            return matchers::sensitive_path_scan_ext(haystack, matchers::BACKUP_EXTENSIONS);
        }
        114 => return matchers::sensitive_path_literal(haystack, matchers::DOUBLE_DOT_BAD),
        117 => return matchers::sensitive_path_management(haystack),
        119 => {
            return matchers::sensitive_path_literal(
                haystack,
                &["actuator", "server-status", "telescope"],
            );
        }
        121 => {
            return matchers::sensitive_path_literal_suffix(
                haystack,
                matchers::RECON_APP_BAD,
                matchers::BadSuffix::DashRun,
            );
        }
        122 => return matchers::sensitive_path_literal(haystack, &["cgi-bin", "cgi-mod"]),
        123 => {
            return matchers::sensitive_path_literal(
                haystack,
                &["HNAP1", "IPCamDesc.xml", "SDK/webLanguage"],
            );
        }
        124 => return matchers::sensitive_path_literal(haystack, &["language", "languages"]),
        125 => {
            return matchers::sensitive_path_literal_suffix_dot(
                haystack,
                matchers::RECON_README_BAD,
            );
        }
        126 => {
            return matchers::sensitive_path_literal(
                haystack,
                &[
                    "sap",
                    "ise",
                    "nidp",
                    "cslu",
                    "rustfs",
                    "developmentserver",
                    "fog/management",
                    "lms/db",
                    "json/login_session",
                    "sms_mp",
                    "plugin/webs_model",
                    "wsman",
                    "am_bin",
                ],
            );
        }
        128 => {
            return matchers::sensitive_path_literal(haystack, &[".openclaw", ".clawdbot"]);
        }
        130 => return matchers::sensitive_path_literal(haystack, &["inicio.html", "inicio.htm"]),
        131 => {
            return matchers::sensitive_path_literal(
                haystack,
                &[
                    ".streamlit",
                    ".gpt-pilot",
                    ".aider",
                    ".cursor",
                    ".windsurf",
                    ".copilot",
                    ".devcontainer",
                ],
            );
        }
        132 => {
            return matchers::sensitive_path_literal_suffix(
                haystack,
                matchers::DOCKERFILE_BAD,
                matchers::BadSuffix::YamlSuffix,
            );
        }
        133 => return matchers::sensitive_path_secrets(haystack),
        134 => return matchers::sensitive_path_literal(haystack, &["autodiscover"]),
        135 => return matchers::sensitive_path_literal(haystack, &["dns-query"]),
        136 => {
            return matchers::sensitive_path_literal(
                haystack,
                &[
                    ".git/refs",
                    ".git/index",
                    ".git/HEAD",
                    ".git/objects",
                    ".git/logs",
                ],
            );
        }
        139 => {
            return matchers::proto_pollution_assign_finditer(haystack);
        }
        144 => return matchers::deserialization_b64_finditer(haystack, "rO0AB"),
        145 => return matchers::deserialization_b64_finditer(haystack, "AAEAAAD"),
        146 => {
            // gA[SW]V: both literal variants with the shared boundary guard
            let mut out = matchers::deserialization_b64_finditer(haystack, "gASV");
            out.extend(matchers::deserialization_b64_finditer(haystack, "gAWV"));
            out.sort_by_key(|c| c.start);
            return out;
        }
        147 => {
            // BAh[Jv7bV]
            let mut out = Vec::new();
            for magic in ["BAhJ", "BAhv", "BAh7", "BAhb", "BAhV"] {
                out.extend(matchers::deserialization_b64_finditer(haystack, magic));
            }
            out.sort_by_key(|c| c.start);
            return out;
        }
        17 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::load_file_scan_matches(haystack, compiled))
                .unwrap_or_default();
        }
        40 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::dollar_substitution_scan_matches(haystack, compiled))
                .unwrap_or_default();
        }
        47 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::shell_dash_c_finditer(haystack, compiled))
                .unwrap_or_default();
        }
        59 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::quote_splice_finditer(haystack, compiled))
                .unwrap_or_default();
        }
        60 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::glob_wildcard_scan_matches(haystack, compiled))
                .unwrap_or_default();
        }
        70 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::ldap_null_byte_attr_raw(haystack, compiled))
                .unwrap_or_default();
        }
        72 => {
            return entry
                .re
                .as_ref()
                .map(|compiled| matchers::ldap_null_byte_attr_decoded(haystack, compiled))
                .unwrap_or_default();
        }
        89..=92 => {
            return file_upload::file_upload_scan_matches(
                haystack,
                source,
                source_of_id(89),
                source_of_id(90),
                source_of_id(91),
                source_of_id(92),
            );
        }
        94 => {
            return templates::template_keyword_matches(
                haystack,
                &templates::KIND_CURLY_KEYWORD,
                true,
            );
        }
        95 => {
            return templates::template_keyword_matches(
                haystack,
                &templates::KIND_PERCENT_KEYWORD,
                true,
            );
        }
        96 => {
            return templates::template_expression_matches(haystack, &templates::KIND_ASP, true);
        }
        97 => {
            return templates::template_expression_matches(haystack, &templates::KIND_DOLLAR, true);
        }
        98 => {
            return templates::template_expression_matches(
                haystack,
                &templates::KIND_CURLY_CALL,
                true,
            );
        }
        99 => {
            return templates::template_expression_matches(haystack, &templates::KIND_HASH, true);
        }
        33 => return matchers::lexicon_path_finditer(haystack, LEXICON_ETC_PATH, true),
        102 => return matchers::lexicon_path_finditer(haystack, LEXICON_ENV_PATH, true),
        107 => return matchers::lexicon_path_finditer(haystack, LEXICON_GIT_PATH, true),
        110 => return matchers::lexicon_path_finditer(haystack, LEXICON_WP_PATH, true),
        112 => return matchers::lexicon_path_finditer(haystack, LEXICON_PHPINFO_PATH, true),
        115 => return matchers::lexicon_path_finditer(haystack, LEXICON_HTACCESS_PATH, true),
        _ => {}
    }
    // plain full-content search
    entry.re.as_ref().map_or_else(Vec::new, |compiled| {
        compiled
            .re()
            .find_iter(haystack)
            .map(|m| Candidate::new(m.start(), m.end()))
            .collect()
    })
}

fn source_of_id(id: usize) -> &'static str {
    table::PATTERN_DEFINITIONS
        .iter()
        .find(|e| e.id == id)
        .map_or("", |e| e.source)
}

/// Lexicon-lookahead path shapes (ids 33/102/107/110/112/115): the reference
/// pattern is `\A(?=LEXICON-in-first-line)\A<path-shape>`; the lexicon
/// membership becomes a guard on the compiled path shape.
pub const LEXICON_ETC_PATH: &str = r"\A[^\n]*[/\\](?:etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf|ssh/ssh_config))(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?\b";
pub const LEXICON_ENV_PATH: &str = r"\A[^\n]*[/\\](?:\.env(?:\.\w+)?)(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?\b";
pub const LEXICON_GIT_PATH: &str = r"\A[^\n]*[/\\](?:\.(?:git|svn|hg|bzr))(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?\b";
pub const LEXICON_WP_PATH: &str = r"\A[^\n]*[/\\](?:(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\.?(?:php)?)(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?\b";
pub const LEXICON_PHPINFO_PATH: &str = r"\A[^\n]*[/\\](?:(?:phpinfo|info|test|php_info)\.php)(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?\b";
pub const LEXICON_HTACCESS_PATH: &str = r"\A[^\n]*[/\\](?:(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db|\.npmrc|\.dockerenv|web\.config))(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?(?:[/\\][\w.\-~%]{1,64})?\b";

/// `_RECON_BARE_PATH_CONTEXTS`: contexts where a recon whole-value hit is a
/// probe regardless of a leading separator.
const RECON_BARE_PATH_CONTEXTS: &[&str] = &["url_path", "unknown"];

/// `_recon_path_value_is_probe`: accepted when the scanned value's base
/// context (validator contexts keep the `:embedded_json` suffix, so split it
/// off) is `url_path` or `unknown`, else the matched text must start with a
/// path separator.
#[must_use]
fn recon_path_value_is_probe(matched: &str, validator_context: &str) -> bool {
    let base = validator_context.split(':').next().unwrap_or("");
    RECON_BARE_PATH_CONTEXTS.contains(&base)
        || matched.starts_with('/')
        || matched.starts_with('\\')
}

/// First accepted regex threat for one entry (validator + recon
/// leading-separator + noise gates).
#[must_use]
pub fn find_first_threat(
    entry: &CompiledEntry,
    haystack: &str,
    context: &str,
    binary_prefix: Option<&[u32]>,
) -> Option<RegexThreat> {
    let noise_prone = table::NOISE_PRONE_PATTERN_SOURCES.contains(entry.entry.source);
    let recon_optional_separator =
        table::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES.contains(entry.entry.source);
    for candidate in pattern_candidates(entry, haystack) {
        if !candidate_accepts(entry, haystack, candidate, context) {
            continue;
        }
        // Upstream guard-core 08f79d67: rows with an optional leading
        // separator must not read bare query or body words as probe paths;
        // ordered after the candidate validators and before the binary-noise
        // gate, mirroring `_build_regex_threat`.
        if recon_optional_separator && !recon_path_value_is_probe(candidate.text(haystack), context)
        {
            continue;
        }
        if noise_prone
            && let Some(prefix) = binary_prefix
            && binary::match_is_binary_density(
                prefix,
                pyregex::cp_index(haystack, candidate.start),
                pyregex::cp_index(haystack, candidate.end),
            )
        {
            continue;
        }
        return Some(RegexThreat {
            pattern: entry.entry.source.to_owned(),
            match_text: candidate.text(haystack).to_owned(),
            position: pyregex::cp_index(haystack, candidate.start),
            category: entry.entry.category.to_owned(),
            weight: resolve_pattern_weight(entry.entry.source),
        });
    }
    None
}

/// Which scan view is being processed; mirrors `_pattern_excluded_from_view`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewFilter {
    /// short-base64 additive view (and legacy checks): no exclusion
    All,
    /// processed view: raw-only and url-decoded-only patterns are excluded
    Processed,
    /// raw signal-preserving view: raw-view-only patterns plus the recon rows
    Raw,
    /// URL-decoded view: only url-decoded-view-only patterns
    UrlDecoded,
}

#[must_use]
pub fn is_excluded_from_view(source: &str, filter: ViewFilter) -> bool {
    let raw_only = table::DETECTION_RAW_VIEW_PATTERN_SOURCES.contains(source);
    let url_only = table::DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES.contains(source);
    // Recon rows also run on the raw view: the processed views fold LDAP hex
    // escapes before the tables run, so separator-prefixed probes such as
    // `\default` only survive there (upstream `DETECTION_RECON_RAW_VIEW_
    // PATTERN_SOURCES`).
    let recon_raw_only = table::DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES.contains(source);
    match filter {
        ViewFilter::All => false,
        ViewFilter::Processed => raw_only || url_only,
        ViewFilter::Raw => url_only || !(raw_only || recon_raw_only),
        ViewFilter::UrlDecoded => raw_only || !url_only,
    }
}

/// Table ids of the size-gated family (guard-core-php PR #1 parity): the
/// `\A`-anchored line-walk and path-segment-loop shapes, skipped when the
/// view's first line reaches `GATED_PATTERN_MAX_SUBJECT_BYTES` bytes.
const SIZE_GATED_IDS: &[usize] = &[
    32, 33, 34, 35, 36, 102, 107, 110, 112, 115, 101, 103, 104, 105, 106, 109, 111, 113, 114, 116,
    117, 119, 121, 122, 123, 124, 125, 126, 128, 130, 131, 132, 133, 134, 135, 136,
];

/// `SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES` (15 KiB).
///
/// The frozen corpus maxes out below the gate, so this never changes
/// conformance outcomes; it ports the reference skip for large single-line
/// bodies.
pub const GATED_PATTERN_MAX_SUBJECT_BYTES: usize = 15_360;

fn first_line_byte_length(content: &str) -> usize {
    content.find('\n').unwrap_or(content.len())
}

fn size_gated(content: &str) -> bool {
    first_line_byte_length(content) >= GATED_PATTERN_MAX_SUBJECT_BYTES
}

/// One view pass of `_check_regex_patterns`: context filter, per-pattern
/// dispatch, validator and binary-density gates, first accepted threat each.
#[must_use]
pub fn scan_view(
    content: &str,
    filter: ViewFilter,
    normalized_context: &str,
    skip_filter: bool,
    validator_context: &str,
) -> Vec<RegexThreat> {
    let binary_prefix = binary::build_binary_prefix(content);
    let gating = size_gated(content);
    let mut threats = Vec::new();
    for entry in COMPILED_TABLE.iter() {
        if is_excluded_from_view(entry.entry.source, filter) {
            continue;
        }
        if !skip_filter && !entry.entry.contexts.contains(&normalized_context) {
            continue;
        }
        if gating && SIZE_GATED_IDS.contains(&entry.entry.id) {
            continue;
        }
        if let Some(threat) =
            find_first_threat(entry, content, validator_context, Some(&binary_prefix))
        {
            threats.push(threat);
        }
    }
    threats
}

/// `_check_decoded_view_path_traversal`: the `\.\.[\\/]` shape fires only
/// when decoding revealed more traversal shapes than the raw view carries.
#[must_use]
pub fn decoded_view_traversal_threat(processed: &str, raw_view: &str) -> Option<RegexThreat> {
    static SHAPE: LazyLock<PyRegex> =
        LazyLock::new(|| PyRegex::compile(r"\.\.[\\/]", false).expect("static shape regex"));
    let decoded_matches: Vec<Candidate> = SHAPE
        .re()
        .find_iter(processed)
        .map(|m| Candidate::new(m.start(), m.end()))
        .collect();
    let raw_count = SHAPE.re().find_iter(raw_view).count();
    if decoded_matches.len() <= raw_count {
        return None;
    }
    let first = decoded_matches[0];
    Some(RegexThreat {
        pattern: r"\.\.[\\/]".to_owned(),
        match_text: first.text(processed).to_owned(),
        position: pyregex::cp_index(processed, first.start),
        category: "path_traversal".to_owned(),
        weight: 1.0,
    })
}

/// The synthetic exhaustion threat appended when a decode pass hit its
/// 16-iteration budget.
#[must_use]
pub fn decode_budget_exhausted_threat() -> RegexThreat {
    RegexThreat {
        pattern: "decode_budget_exhausted".to_owned(),
        match_text: "decode_budget_exhausted".to_owned(),
        position: 0,
        category: "custom".to_owned(),
        weight: 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_for(id: usize) -> &'static CompiledEntry {
        COMPILED_TABLE
            .iter()
            .find(|e| e.entry.id == id)
            .expect("entry exists")
    }

    fn threat(id: usize, content: &str) -> Option<RegexThreat> {
        find_first_threat(entry_for(id), content, "request_body", None)
    }

    #[test]
    fn compiled_table_is_complete() {
        assert_eq!(COMPILED_TABLE.len(), table::PATTERN_DEFINITIONS.len());
    }

    #[test]
    fn script_threat_position_and_text() {
        let t = threat(0, "x<script>alert(1)</script>y").expect("script threat");
        assert_eq!(t.match_text, "<script>alert(1)</script>");
        assert_eq!(t.position, 1);
        assert_eq!(t.category, "xss");
    }

    #[test]
    fn etc_passwd_via_url_decoded_view_source() {
        let t = threat(32, "O:8:\"T\":1:{s:4:\"file\";s:11:\"/etc/passwd\";}").expect("etc threat");
        assert_eq!(t.position, 0);
        assert_eq!(t.category, "dir_traversal");
    }

    #[test]
    fn select_from_union_case() {
        let t = threat(9, "id=1 UNION SELECT 1 FROM (SELECT 1)a--").expect("select threat");
        // leftmost \bSELECT\b is inside "UNION SELECT"
        assert_eq!(t.position, 11);
        assert_eq!(t.match_text, "SELECT 1 FROM");
    }

    #[test]
    fn tautology_match() {
        let t = threat(12, "' OR 1=1--").expect("tautology");
        assert_eq!(t.position, 2);
        assert_eq!(t.match_text, "OR 1=1");
    }

    #[test]
    fn union_select_weight_one() {
        let t = threat(13, "' UNION SELECT NULL, NULL, NULL--").expect("union");
        assert_eq!(t.position, 2);
        assert!((t.weight - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn where_clause_weight_half() {
        let t = threat(11, "UPDATE users SET admin=true WHERE id=1").expect("where");
        assert_eq!(t.position, 28);
        assert!((t.weight - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn log4shell_and_ssrf() {
        let content = "${jndi:ldap://10.0.0.1/a}";
        let t44 = threat(44, content).expect("log4shell");
        assert_eq!(t44.position, 0);
        let t78 = threat(78, content).expect("ssrf private");
        assert_eq!(t78.position, 13);
        let t79 = threat(79, content).expect("ssrf numeric");
        assert_eq!(t79.position, 11);
    }

    #[test]
    fn ldap_injection_validators() {
        let content = "*)(uid=*))(|(uid=*";
        assert!(threat(65, content).is_some(), "paren conj star");
        assert!(threat(68, content).is_some(), "paren conjunction");
        assert!(threat(67, content).is_some(), "paren breakout");
        assert!(threat(69, content).is_some(), "wildcard chain");
        assert!(threat(66, content).is_some(), "wildcard equals");
    }

    #[test]
    fn ldap_conjunction_followup() {
        // conjunction + followup clause is the injection canary
        assert!(threat(68, "(&(objectClass=user))").is_some());
        // bare conjunction without followup is rejected
        assert!(threat(68, "(|x").is_none());
    }

    #[test]
    fn sensitive_paths() {
        assert!(threat(101, "/.env").is_some());
        assert!(threat(106, "/.git/config").is_some());
        assert!(threat(117, "/.aws/credentials").is_some());
        assert!(threat(114, "/.htpasswd").is_some());
        assert!(threat(113, "/config.php.bak").is_some());
        assert!(threat(109, "/wp-login.php").is_some());
        assert!(threat(119, "/actuator/env").is_some());
        assert!(threat(109, "/admin/login/?next=/admin/").is_none());
        assert!(threat(105, "/admin/login/?next=/admin/").is_none());
    }

    #[test]
    fn file_upload_kinds() {
        assert!(threat(89, "filename=\"shell.phtml\"").is_some());
        assert!(threat(90, "filename=\"shell.php.jpg\"").is_some());
        assert!(threat(89, "filename=\".htaccess\"").is_none());
    }

    #[test]
    fn templates() {
        assert!(threat(98, "{{ 7 * 7 }}").is_some());
        assert!(threat(97, "${7 * 7}").is_some());
        assert!(threat(96, "<%= 7 * 7 %>").is_some());
        assert!(threat(97, "#set($x = 7 * 7)$x").is_none());
    }

    #[test]
    fn deser_magic_prefixes() {
        assert!(threat(144, "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==").is_some());
        assert!(threat(144, "cHl0aG9u").is_none());
    }

    #[test]
    fn pickle_global_validator() {
        let payload = "cos\nsystem\n(S'id'\ntR.";
        assert!(threat(152, payload).is_some(), "pickle reduce");
        assert!(threat(152, "cos\nsystem\n(S'id'\n.").is_none(), "no reduce");
    }

    #[test]
    fn dollar_substitution_validator() {
        assert!(threat(43, "cat${IFS}/etc/passwd").is_some(), "IFS special");
        // plausible $() token only fires in the ambiguous contexts
        assert!(threat(43, "$(whoami)").is_none(), "request_body reject");
        assert!(threat(43, "total cost is $100 after discount").is_none());
    }

    #[test]
    fn backtick_chain_and_candidate() {
        assert!(threat(41, "`id`").is_some(), "full chain");
        // the glued candidate fires only when its validator accepts; bare
        // `id` with no glue is rejected by the candidate validator
        assert!(threat(42, "`id`").is_none(), "candidate rejected");
    }

    #[test]
    fn comment_terminator_raw_view() {
        assert!(threat(29, "admin'--").is_some());
        let t = threat(29, "'; EXEC xp_cmdshell('dir')--").expect("comment");
        assert_eq!(t.position, 24);
        assert_eq!(t.match_text, "')--");
    }

    #[test]
    fn http_split_position() {
        let t = threat(100, "en\r\nSet-Cookie: injected=1").expect("http split");
        assert_eq!(t.position, 3);
    }

    #[test]
    fn xss_event_handler_cases() {
        assert!(threat(3, "<img src=x onerror=alert(1)>").is_some());
        assert!(threat(3, "/search?q=<svg/onload=alert(1)>").is_some());
        // oracle-verified: the lookbehinds reject the SEQUENCES `=`/`="/`='`;
        // a bare `"` before the run does not block, and the greedy group
        // picks the rightmost split
        let t = threat(3, "<img src=\"x\" onerror=alert(1)>").expect("quoted attr matches");
        assert_eq!(t.match_text, "<img src=\"x\" onerror=alert(1)");
        assert!(threat(3, "<b>bold</b> text").is_none());
    }

    #[test]
    fn inline_comment_obfuscation() {
        assert!(threat(21, "UNI/**/ON SE/**/LECT 1,2,3").is_some());
        // /*! is protected in the reference table too (distinct pattern id 20)
        assert!(threat(21, "UNI/*!*/ON").is_none());
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn decode_budget_exhausted_threat_carries_the_marker() {
        let threat = decode_budget_exhausted_threat();
        assert_eq!(threat.pattern, "decode_budget_exhausted");
        assert_eq!(threat.match_text, "decode_budget_exhausted");
        assert_eq!(threat.position, 0);
        assert_eq!(threat.category, "custom");
    }

    #[test]
    fn structural_candidates_route_through_the_validators() {
        // id 58: brace expansion
        let entry = |id: usize| COMPILED_TABLE.iter().find(|e| e.entry.id == id).unwrap();
        assert!(candidate_accepts(
            entry(58),
            "cmd {a,b}",
            Candidate::new(4, 9),
            "arg"
        ));
        assert!(!candidate_accepts(
            entry(58),
            "plain",
            Candidate::new(0, 5),
            "arg"
        ));
        // id 59: quote splice (three 1-char fragments)
        let content = "a'b'c";
        assert!(candidate_accepts(
            entry(59),
            content,
            Candidate::new(0, 5),
            "arg"
        ));
        // id 105: source extension path probe
        assert!(candidate_accepts(
            entry(105),
            "",
            Candidate::new(0, 0),
            "url_path:.php"
        ));
    }

    #[test]
    fn ldap_candidate_routes_fall_back_to_accepting_when_uncompiled() {
        // a compiled entry whose regex source is stripped: the fallback
        // accepts rather than silently filtering
        let entry = COMPILED_TABLE.iter().find(|e| e.entry.id == 66).unwrap();
        let stripped_entry = CompiledEntry {
            entry: crate::patterns::table::TableEntry {
                id: entry.entry.id,
                source: entry.entry.source,
                contexts: entry.entry.contexts,
                category: entry.entry.category,
            },
            re: None,
        };
        assert!(candidate_accepts(
            &stripped_entry,
            "x",
            Candidate::new(0, 1),
            "arg"
        ));
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn the_conjunction_validator_falls_back_to_accepting_when_uncompiled() {
        // id 68 (paren conjunction) with its regex stripped: the fallback
        // accepts rather than silently filtering
        let entry = COMPILED_TABLE.iter().find(|e| e.entry.id == 68).unwrap();
        let stripped_entry = CompiledEntry {
            entry: crate::patterns::table::TableEntry {
                id: entry.entry.id,
                source: entry.entry.source,
                contexts: entry.entry.contexts,
                category: entry.entry.category,
            },
            re: None,
        };
        assert!(candidate_accepts(
            &stripped_entry,
            "x",
            Candidate::new(0, 1),
            "arg"
        ));
    }
}
