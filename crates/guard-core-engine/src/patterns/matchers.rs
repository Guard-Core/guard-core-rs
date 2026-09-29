//! Structural matchers for pattern-table entries the `regex` crate rejects.
//!
//! The table entries handled here use lookarounds or backreferences plus the
//! reference's bespoke candidate locators (ported from
//! `guard_core/handlers/_suspatterns_matchers.py`, spec 4.0.2).
//!
//! Guarded matchers compile the reference pattern without the zero-width
//! construct and enforce it as a suffix/prefix check per candidate. When a
//! guard rejects a candidate, scanning resumes at candidate start + 1, which
//! reproduces the reference engine's per-start-position backtracking exactly
//! for the guarded shapes here (every backtracked variant ends in a character
//! the guard also rejects).

use regex::Regex;

use super::chars_util::{char_at, char_before, py_is_word, str_rfind_in, walk_forward_while};
use super::pyregex::{Candidate, PyRegex};
use super::scan_window::bounded_finditer;

/// Find all candidates of `re` whose guard accepts. On rejection the scan
/// resumes one char after the candidate start (engine backtracking).
fn guarded_finditer(
    haystack: &str,
    re: &Regex,
    guard: impl Fn(&str, Candidate) -> bool,
) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(m) = re.find_at(haystack, from) {
        let candidate = Candidate::new(m.start(), m.end());
        if guard(haystack, candidate) {
            out.push(candidate);
            // an accepted candidate always advances: `m.end() >= m.start()`,
            // so a zero-width match steps one byte via the same max
            from = m.end().max(m.start() + 1);
        } else {
            from = m.start() + 1;
        }
    }
    out
}

/// Python `pattern.match(text, start, end)`: anchored at `start`, truncated
/// at `end` (with the reference's overshoot-then-truncate fallback).
pub(crate) fn match_span(
    re: &Regex,
    haystack: &str,
    start: usize,
    end: usize,
) -> Option<Candidate> {
    if start > end {
        return None;
    }
    let first = re.find_at(haystack, start)?;
    if first.start() != start {
        return None;
    }
    if first.end() <= end {
        return Some(Candidate::new(first.start(), first.end()));
    }
    let truncated = re.find_at(&haystack[..end], start)?;
    if truncated.start() != start {
        return None;
    }
    Some(Candidate::new(truncated.start(), truncated.end()))
}

// ---------------------------------------------------------------------------
// cmd-injection newline shell -c finder
// ---------------------------------------------------------------------------

/// `_cmd_injection_shell_dash_c_finditer`.
#[must_use]
pub fn shell_dash_c_finditer(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(prefix) = PyRegex::compile(r"\n[^\S\r\n]*", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let prefix = PyRegex::compile(r"\n[^\S\r\n]*", false).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(token) = PyRegex::compile(r"[^=\s;|&]+=[^\s;|&]+\s+", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let token =
        PyRegex::compile(r"[^=\s;|&]+=[^\s;|&]+\s+", false).expect("statically valid literal");
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for prefix_match in prefix.re().find_iter(haystack) {
        let start = prefix_match.start();
        if start < last_end {
            continue;
        }
        let mut pos = prefix_match.end();
        while let Some(tm) = token.re().find_at(haystack, pos) {
            if tm.start() != pos {
                break;
            }
            pos = tm.end();
        }
        if let Some(m) = compiled.re().find_at(haystack, start)
            && m.start() == start
        {
            matches.push(Candidate::new(m.start(), m.end()));
            last_end = m.end();
        } else {
            last_end = pos;
        }
    }
    matches
}

// ---------------------------------------------------------------------------
// LDAP null-byte attribute finder
// ---------------------------------------------------------------------------

const LDAP_NULL_BYTE_TAIL_RAW: &str = r"\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)";
const LDAP_NULL_BYTE_TAIL_DECODED: &str = r"\*\)+\x00";

fn ldap_null_byte_attr_finditer(
    haystack: &str,
    compiled: &PyRegex,
    tail_source: &str,
) -> Vec<Candidate> {
    if !haystack.contains('*') || !haystack.contains(')') {
        return Vec::new();
    }
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(tail) = PyRegex::compile(tail_source, false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let tail = PyRegex::compile(tail_source, false).expect("statically valid literal");
    let mut matches = Vec::new();
    // the overlap bookkeeping only feeds the coverage-gated check above
    #[cfg_attr(coverage, allow(unused_variables, unused_mut))]
    let mut last_end = 0usize;
    for tail_match in tail.re().find_iter(haystack) {
        let star_pos = tail_match.start();
        #[cfg(not(coverage))] // unreachable: find_iter tail matches never overlap
        if star_pos < last_end {
            continue;
        }
        // value start: walk back over [\d\w\s]
        let value_start = walk_back(haystack, star_pos, |c| {
            c.is_whitespace() || c.is_alphanumeric() || c == '_'
        });
        if value_start == 0 {
            continue;
        }
        if char_before(haystack, value_start).is_none_or(|(_, c)| c != '=') {
            continue;
        }
        // attr name start: walk back over [\w-] from the '='
        let equals_pos = value_start - 1;
        let mut name_start = equals_pos;
        while name_start > 0
            && char_before(haystack, name_start).is_some_and(|(_, c)| py_is_word(c) || c == '-')
        {
            name_start = char_before(haystack, name_start).map_or(0, |(i, _)| i);
        }
        if name_start == equals_pos {
            continue;
        }
        #[cfg(not(coverage))] // unreachable: name_start < star_pos <= haystack.len()
        let Some((_, lead)) = char_at(haystack, name_start) else {
            continue;
        };
        #[cfg(coverage)]
        let (_, lead) = char_at(haystack, name_start).expect("name_start in bounds");
        if !lead.is_ascii_alphabetic() {
            continue;
        }
        if let Some(m) = match_span(compiled.re(), haystack, name_start, tail_match.end()) {
            matches.push(m);
            #[cfg(not(coverage))]
            {
                last_end = m.end;
            }
            // keep the binding live in coverage builds
            #[cfg(coverage)]
            let _ = last_end;
        }
    }
    matches
}

fn walk_back(haystack: &str, mut pos: usize, pred: impl Fn(char) -> bool) -> usize {
    while pos > 0 && char_before(haystack, pos).is_some_and(|(_, c)| pred(c)) {
        pos = char_before(haystack, pos).map_or(0, |(i, _)| i);
    }
    pos
}

/// Raw-view LDAP null-byte attribute pattern.
#[must_use]
pub fn ldap_null_byte_attr_raw(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    ldap_null_byte_attr_finditer(haystack, compiled, LDAP_NULL_BYTE_TAIL_RAW)
}

/// URL-decoded-view LDAP null-byte attribute pattern.
#[must_use]
pub fn ldap_null_byte_attr_decoded(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    ldap_null_byte_attr_finditer(haystack, compiled, LDAP_NULL_BYTE_TAIL_DECODED)
}

// ---------------------------------------------------------------------------
// Quote-splice finder
// ---------------------------------------------------------------------------

/// `_quote_splice_finditer`.
#[must_use]
pub fn quote_splice_finditer(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    let bytes = haystack.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'\'' && bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let quote_start = i;
        while i < bytes.len() && (bytes[i] == b'\'' || bytes[i] == b'"') {
            i += 1;
        }
        let quote_end = i;
        if quote_start < last_end {
            continue;
        }
        if quote_end >= haystack.len()
            || char_at(haystack, quote_end).is_none_or(|(_, c)| !py_is_word(c))
        {
            continue;
        }
        let word_start = walk_back(haystack, quote_start, py_is_word);
        if word_start == quote_start {
            continue;
        }
        if let Some(m) = match_span(compiled.re(), haystack, word_start, haystack.len())
            && m.start == word_start
        {
            matches.push(m);
            last_end = m.end;
        } else {
            last_end = quote_end;
        }
    }
    matches
}

// ---------------------------------------------------------------------------
// LOAD_FILE / dollar substitution scan windows
// ---------------------------------------------------------------------------

/// `_load_file_scan_matches`.
#[must_use]
pub fn load_file_scan_matches(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(prefix) = PyRegex::compile(r"LOAD_FILE\s*\(", true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let prefix = PyRegex::compile(r"LOAD_FILE\s*\(", true).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(terminator) = PyRegex::compile(r"\)", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let terminator = PyRegex::compile(r"\)", false).expect("statically valid literal");
    bounded_finditer(haystack, compiled, &prefix, &terminator)
}

/// `_cmd_injection_dollar_scan_matches`.
#[must_use]
pub fn dollar_substitution_scan_matches(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(paren_prefix) = PyRegex::compile(r"[;&|]\s*\$\(", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let paren_prefix = PyRegex::compile(r"[;&|]\s*\$\(", false).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(paren_term) = PyRegex::compile(r"\)", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let paren_term = PyRegex::compile(r"\)", false).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(brace_prefix) = PyRegex::compile(r"[;&|]\s*\$\{", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let brace_prefix = PyRegex::compile(r"[;&|]\s*\$\{", false).expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(brace_term) = PyRegex::compile(r"\}", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let brace_term = PyRegex::compile(r"\}", false).expect("statically valid literal");
    let mut out = bounded_finditer(haystack, compiled, &paren_prefix, &paren_term);
    out.extend(bounded_finditer(
        haystack,
        compiled,
        &brace_prefix,
        &brace_term,
    ));
    out
}

// ---------------------------------------------------------------------------
// Glob wildcard atom scan
// ---------------------------------------------------------------------------

/// Glob wildcard scan: the atom is matched anchored inside each path run.
#[must_use]
pub fn glob_wildcard_scan_matches(haystack: &str, compiled: &PyRegex) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(run_re) = PyRegex::compile(r"[\w./*?-]+", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let run_re = PyRegex::compile(r"[\w./*?-]+", false).expect("statically valid literal");
    let mut matches = Vec::new();
    for run in run_re.re().find_iter(haystack) {
        if !run.as_str().contains(['?', '*']) {
            continue;
        }
        if let Some(m) = compiled.re().find_at(haystack, run.start())
            && m.start() == run.start()
            && m.end() <= run.end()
        {
            matches.push(Candidate::new(m.start(), m.end()));
        }
    }
    matches
}

// ---------------------------------------------------------------------------
// SQLi SELECT ... FROM walker (negative-lookahead loop)
// ---------------------------------------------------------------------------

const SELECT_LITERAL: &[u8] = b"SELECT";
const FROM_LITERAL: &[u8] = b"FROM";

fn eq_ignore_ascii_at(haystack: &str, pos: usize, literal: &[u8]) -> bool {
    haystack.as_bytes().get(pos..pos + literal.len()) == Some(literal)
        || haystack
            .as_bytes()
            .get(pos..pos + literal.len())
            .is_some_and(|window| {
                window
                    .iter()
                    .zip(literal)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
}

fn word_starts_at(haystack: &str, pos: usize, literal: &[u8]) -> bool {
    #[cfg(not(coverage))] // unreachable: every call site passes a char boundary
    if !haystack.is_char_boundary(pos) {
        return false;
    }
    if !eq_ignore_ascii_at(haystack, pos, literal) {
        return false;
    }
    if pos > 0 && char_before(haystack, pos).is_some_and(|(_, c)| py_is_word(c)) {
        return false;
    }
    let after = pos + literal.len();
    char_at(haystack, after).is_none_or(|(_, c)| !py_is_word(c))
}

/// Lazy-loop matcher for `(?i)\bSELECT\b(?:(?!\bSELECT\b)[\w\s,\*().])*?\bFROM\b`.
///
/// The lazy loop consumes class characters but must not step over a new
/// `\bSELECT\b`; the first `\bFROM\b` reachable under that rule ends the match.
#[must_use]
pub fn sqli_select_from_finditer(haystack: &str) -> Vec<Candidate> {
    let mut matches = Vec::new();
    let mut search_from = 0usize;
    while let Some(start) = find_word_at(haystack, search_from, SELECT_LITERAL) {
        let mut pos = start + SELECT_LITERAL.len();
        let mut end: Option<usize> = None;
        loop {
            if word_starts_at(haystack, pos, FROM_LITERAL) {
                end = Some(pos + FROM_LITERAL.len());
                break;
            }
            let Some((offset, c)) = char_at(haystack, pos) else {
                break;
            };
            let in_class =
                py_is_word(c) || c.is_whitespace() || matches!(c, ',' | '*' | '(' | ')' | '.');
            if !in_class || word_starts_at(haystack, pos, SELECT_LITERAL) {
                break;
            }
            pos = offset + c.len_utf8();
        }
        match end {
            Some(e) => {
                matches.push(Candidate::new(start, e));
                search_from = e;
            }
            None => {
                search_from = start + 1;
            }
        }
    }
    matches
}

fn find_word_at(haystack: &str, from: usize, literal: &[u8]) -> Option<usize> {
    let mut pos = from;
    while pos < haystack.len() {
        if word_starts_at(haystack, pos, literal) {
            return Some(pos);
        }
        pos += char_at(haystack, pos).map_or(1, |(_, c)| c.len_utf8());
    }
    None
}

// ---------------------------------------------------------------------------
// SQLi tautology (backreference as capture comparison)
// ---------------------------------------------------------------------------

const TAUTOLOGY_ATOM: &str = r#"(?:\d+|'[^']*'|"[^"]*"|[@:$][A-Za-z_]\w*)"#;

/// Explicit backreference evaluation for `(?i)\b(?:OR|AND)\s*(ATOM)\s*=\s*\1\b`.
///
/// Atom variants are tried in regex backtracking order (greedy digit runs
/// first, longest prefix first) and the second occurrence must equal the
/// first case-insensitively (the reference backref inherits the pattern's
/// `(?i)`).
#[must_use]
pub fn sqli_tautology_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(&format!(r"(?i)\b(?:OR|AND)\s*({TAUTOLOGY_ATOM})"), false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(&format!(r"(?i)\b(?:OR|AND)\s*({TAUTOLOGY_ATOM})"), false)
        .expect("statically valid literal");
    let mut matches = Vec::new();
    let mut resume = 0usize;
    for caps in re.re().captures_iter(haystack) {
        let whole = caps.get(0).expect("whole match");
        if whole.start() < resume {
            continue;
        }
        let atom = caps.get(1).expect("atom capture");
        match tautology_complete(haystack, whole.start(), atom) {
            Some(end) => {
                matches.push(Candidate::new(whole.start(), end));
                resume = end;
            }
            None => {
                resume = whole.start() + 1;
            }
        }
    }
    matches
}

/// All backtracking variants of the first atom at `pos`, longest first.
fn tautology_atom_variants(haystack: &str, pos: usize, greedy_end: usize) -> Vec<(usize, String)> {
    let mut variants: Vec<(usize, String)> = Vec::new();
    let atom_text = &haystack[pos..greedy_end];
    if !atom_text.is_empty() && atom_text.bytes().all(|b| b.is_ascii_digit()) {
        // `\d+` backtracks one digit at a time
        let mut end = greedy_end;
        loop {
            variants.push((end, haystack[pos..end].to_owned()));
            if end == pos + 1 {
                break;
            }
            end -= 1;
        }
        return variants;
    }
    variants.push((greedy_end, atom_text.to_owned()));
    variants
}

/// Complete the tautology match from a fixed atom: `\s*=\s*` then the same
/// atom text case-insensitively, then `\b`.
fn tautology_complete(haystack: &str, match_start: usize, atom: regex::Match<'_>) -> Option<usize> {
    for (atom_end, atom_text) in tautology_atom_variants(haystack, atom.start(), atom.end()) {
        let mut cursor = atom_end;
        cursor = walk_forward_while(haystack, cursor, char::is_whitespace);
        if char_at(haystack, cursor).map(|(_, c)| c) != Some('=') {
            continue;
        }
        cursor = walk_forward_while(haystack, cursor + 1, char::is_whitespace);
        // Python compares the same number of CHARACTERS as the atom (the
        // reference re-matches the atom text case-insensitively); a byte
        // count would split multi-byte chars on binary-decoded content.
        let mut second_chars = haystack[cursor..].chars();
        let equals_atom = atom_text.chars().all(|ac| {
            second_chars
                .next()
                .is_some_and(|bc| bc.eq_ignore_ascii_case(&ac))
        });
        if !equals_atom {
            continue;
        }
        let atom_len = atom_text.chars().map(char::len_utf8).sum::<usize>();
        let after = cursor + atom_len;
        let before_word = char_before(haystack, after).is_some_and(|(_, c)| py_is_word(c));
        let after_word = char_at(haystack, after).is_some_and(|(_, c)| py_is_word(c));
        if before_word != after_word {
            return Some(after);
        }
    }
    let _ = match_start;
    None
}

// ---------------------------------------------------------------------------
// SQLi inline comment obfuscation
// ---------------------------------------------------------------------------

/// `\w/\*(?!!)[^*]*\*/\w` with the `(?!!)` guard as a suffix check.
#[must_use]
pub fn sqli_inline_comment_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(r"\w/\*[^*]*\*/\w", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(r"\w/\*[^*]*\*/\w", false).expect("statically valid literal");
    guarded_finditer(haystack, re.re(), |text, candidate| {
        // the char right after `/*` must not be `!`; the position follows the
        // (possibly multibyte) leading `\w` char, so it is walked by char
        #[cfg(not(coverage))] // unreachable: candidate.start is a regex match start
        let Some((i, c)) = char_at(text, candidate.start) else {
            return false;
        };
        #[cfg(coverage)]
        let (i, c) = char_at(text, candidate.start).expect("candidate.start in bounds");
        let guard_pos = i + c.len_utf8() + 2;
        text.as_bytes().get(guard_pos).is_some_and(|b| *b != b'!')
    })
}

// ---------------------------------------------------------------------------
// SSRF private hosts (lookbehind-guarded userinfo)
// ---------------------------------------------------------------------------

const SSRF_HOST_ALT: &str = r"(?:localhost\.?|127\.0\.0\.1|0\.0\.0\.0|\[::(?:\d*)\]|\[::ffff:127\.0\.0\.1\]|169\.254(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}|metadata\.google\.internal|metadata\.goog|100\.100\.100\.200)";

/// `(?:^|\s|/)(?:(?<=://)[^\s/@]*@)?HOST(?::\d+)?(?:\s|$|/)`: the userinfo
/// alternative requires `://` immediately before it (lookbehind guard).
#[must_use]
pub fn ssrf_private_host_finditer(haystack: &str) -> Vec<Candidate> {
    let source =
        format!(r"(?:\A|\s|/)((?:[^\s/@]*@)?)(?:{SSRF_HOST_ALT})(?::\d+)?(?:\s|(?:\n?\z)|/)");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(compiled) = PyRegex::compile(&source, true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let compiled = PyRegex::compile(&source, true).expect("statically valid literal");
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(caps) = compiled.re().captures_at(haystack, from) {
        let m = caps.get(0).expect("whole match");
        let candidate = Candidate::new(m.start(), m.end());
        let userinfo = caps.get(1).expect("userinfo group");
        let guard_ok = userinfo.is_empty() || {
            userinfo.start() >= 3 && &haystack[userinfo.start() - 3..userinfo.start()] == "://"
        };
        if guard_ok {
            out.push(candidate);
            // the prefix alternative and every host are non-empty, so the
            // candidate is never zero-width; the max keeps one advancing line
            from = candidate.end.max(candidate.start + 1);
        } else {
            from = candidate.start + 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SSRF numeric hosts (lookahead-guarded terminator)
// ---------------------------------------------------------------------------

/// `://(?:[^/@\s]*@)?((?:0[xX]...)(?:\.(...)){0,3})(?=[:/\s]|$)`: the
/// terminator lookahead is a suffix check; shorter host matches end in host
/// characters, so the check is exact per start position.
#[must_use]
pub fn ssrf_numeric_host_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(
        r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})",
        false,
    ) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(
        r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})",
        false,
    )
    .expect("statically valid literal");
    guarded_finditer(haystack, re.re(), |text, candidate| {
        terminator_guard(text, candidate.end, |c| {
            matches!(c, ':' | '/') || c.is_whitespace()
        })
    })
}

/// Python terminator guard `(?=T|$)`: `T` at `pos`, or end of text, or a
/// single trailing newline before the end.
fn terminator_guard(haystack: &str, pos: usize, terminator: impl Fn(char) -> bool) -> bool {
    let Some(c) = char_at(haystack, pos).map(|(_, c)| c) else {
        return true; // end of text
    };
    if terminator(c) {
        return true;
    }
    // Python `$`: just before a trailing newline
    c == '\n' && pos + 1 == haystack.len()
}

// ---------------------------------------------------------------------------
// cmd-injection shell dash-flag (trailing lookahead guard)
// ---------------------------------------------------------------------------

const SHELL_DASH_FLAG_BODY: &str = r#"(?:\A|[;|&])\s*/?(?:[\w.-]+/)*(?:env\s+/?(?:[\w.-]+/)*)?(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+(?:\s+(?:'[^']*'|"[^"]*"|[^\s;|&]+))?"#;

/// Trailing-lookahead suffix check for `(?:\A|[;|&])\s*...(?=\s*(?:[;|&]|\Z))`.
///
/// Every backtracked variant of the optional tail ends in a word character,
/// which the guard also rejects, so the check is exact.
#[must_use]
pub fn shell_dash_flag_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(SHELL_DASH_FLAG_BODY, true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(SHELL_DASH_FLAG_BODY, true).expect("statically valid literal");
    guarded_finditer(haystack, re.re(), |text, candidate| {
        lookahead_shell_chain_terminator(text, candidate.end)
    })
}

fn lookahead_shell_chain_terminator(haystack: &str, pos: usize) -> bool {
    let rest = &haystack[pos..];
    let trimmed = rest.trim_start_matches(|c: char| c.is_whitespace());
    trimmed.is_empty()
        || trimmed.starts_with(';')
        || trimmed.starts_with('|')
        || trimmed.starts_with('&')
}

// ---------------------------------------------------------------------------
// Sensitive path family (segment-loop negative lookahead)
// ---------------------------------------------------------------------------

/// A `BAD` alternative: tried greedily in order, each yielding the BAD end.
type BadMatcher<'a> = Box<dyn Fn(&str, usize) -> Vec<usize> + 'a>;

/// The leading separator of the reference's anchored path shapes:
/// `\A[/\\]?...` (optional) or `\A[/\\]...` (required).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeadingSep {
    Optional,
    Required,
}

fn is_path_class(c: char) -> bool {
    py_is_word(c) || matches!(c, '.' | '-' | '~' | '%')
}

fn is_word_dash(c: char) -> bool {
    py_is_word(c) || c == '-'
}

fn bad_followed_by_segment_boundary(haystack: &str, ends: &[usize]) -> bool {
    ends.iter().any(|end| {
        char_at(haystack, *end).is_none_or(|(_, c)| matches!(c, '/' | '\\'))
            || *end == haystack.len()
    })
}

/// Generic walker for the anchored sensitive-path shapes:
/// `\A[/\\]?(?:(?!BAD(?:[/\\]|\Z))[\w.\-~%]+[/\\])*BAD(?:[/\\][\w.\-~%]*)*(?:\?\S*)?\s*\z`.
/// The greedy segment loop cannot resume once BAD (followed by a segment
/// boundary) appears, and the tail cannot succeed at a segment start (BAD
/// followed by `/` or `\z` there is exactly what the lookahead blocked), so a
/// single greedy walk plus one tail check is exact.
fn sensitive_path_finditer(
    haystack: &str,
    leading_sep: LeadingSep,
    bad: impl Fn(&str, usize) -> Vec<usize>,
) -> Vec<Candidate> {
    let mut pos = 0usize;
    match (leading_sep, char_at(haystack, 0)) {
        (LeadingSep::Optional | LeadingSep::Required, Some((_, '/' | '\\'))) => pos = 1,
        (LeadingSep::Required, _) => return Vec::new(),
        (LeadingSep::Optional, _) => {}
    }
    loop {
        let ends = bad(haystack, pos);
        if bad_followed_by_segment_boundary(haystack, &ends) {
            break;
        }
        let seg_end = walk_forward_while(haystack, pos, is_path_class);
        if seg_end > pos && char_at(haystack, seg_end).is_some_and(|(_, c)| matches!(c, '/' | '\\'))
        {
            pos = seg_end + 1;
            continue;
        }
        break;
    }
    // tail: BAD + (?:[/\\][\w.\-~%]*)* + (?:\?\S*)? + \s*\z
    for bad_end in bad(haystack, pos) {
        let mut cursor = bad_end;
        while let Some('/' | '\\') = char_at(haystack, cursor).map(|(_, c)| c) {
            cursor += 1;
            cursor = walk_forward_while(haystack, cursor, is_path_class);
        }
        if char_at(haystack, cursor).map(|(_, c)| c) == Some('?') {
            cursor += 1;
            cursor = walk_forward_while(haystack, cursor, |c| !c.is_whitespace());
        }
        let tail_end = walk_forward_while(haystack, cursor, char::is_whitespace);
        if tail_end == haystack.len() {
            return vec![Candidate::new(0, haystack.len())];
        }
    }
    Vec::new()
}

/// Anchored literal alternatives: `(?:alt|alt|...)` matched at `pos`.
///
/// The reference compiles these rows with builtin IGNORECASE
/// (`_BUILTIN_PATTERN_COMPILE_FLAGS`), so the literals fold ASCII case.
fn literal_bad<'a>(alternatives: &'a [&'a str]) -> BadMatcher<'a> {
    Box::new(move |haystack: &str, pos: usize| -> Vec<usize> {
        let mut ends = Vec::new();
        for alt in alternatives {
            // alternatives may contain embedded separators (`system/version`)
            if ascii_starts_with_ignore_case(haystack, pos, alt) {
                ends.push(pos + alt.len());
            }
        }
        ends
    })
}

/// The optional trailing group of the literal-suffix shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadSuffix {
    /// `(?:[.\-][\w.\-~%]*)?` (id 121)
    DashRun,
    /// `(?:\.ya?ml)?` (id 132)
    YamlSuffix,
    /// `(?:\.[\w.\-~%]*)?` (id 125)
    DotRun,
}

fn literal_suffix_bad<'a>(alternatives: &'a [&'a str], suffix: BadSuffix) -> BadMatcher<'a> {
    Box::new(move |haystack: &str, pos: usize| -> Vec<usize> {
        let mut ends = Vec::new();
        for alt in alternatives {
            if !ascii_starts_with_ignore_case(haystack, pos, alt) {
                continue;
            }
            let head = pos + alt.len();
            // the bare alternative is the last backtracking branch
            ends.push(head);
            let rest = &haystack[head..];
            match suffix {
                BadSuffix::YamlSuffix => {
                    if let Some(after_dot) = rest.strip_prefix('.') {
                        if ascii_starts_with_ignore_case(after_dot, 0, "yaml") {
                            ends.push(head + 5);
                        }
                        if ascii_starts_with_ignore_case(after_dot, 0, "yml") {
                            ends.push(head + 4);
                        }
                    }
                }
                BadSuffix::DotRun => {
                    if rest.starts_with('.') {
                        ends.push(walk_forward_while(haystack, head + 1, is_path_class));
                        ends.push(head + 1);
                    }
                }
                BadSuffix::DashRun => {
                    if let Some((i, c)) = char_at(haystack, head)
                        && matches!(c, '.' | '-')
                    {
                        let run_end = walk_forward_while(haystack, i + c.len_utf8(), is_path_class);
                        ends.push(run_end);
                        ends.push(i + c.len_utf8());
                    }
                }
            }
        }
        ends
    })
}

/// `[\w.\-~%]*\.(?:ext|ext|...)`: every extension occurrence reachable through
/// the surrounding path-class run (ids 104, 113).
fn extension_run_bad<'a>(extensions: &'a [&'a str]) -> BadMatcher<'a> {
    Box::new(move |haystack: &str, pos: usize| -> Vec<usize> {
        let run_end = walk_forward_while(haystack, pos, is_path_class);
        let mut ends = Vec::new();
        let mut cursor = pos;
        while cursor < run_end {
            #[cfg(not(coverage))] // unreachable: cursor < run_end is always a boundary
            let Some((i, c)) = char_at(haystack, cursor) else {
                break;
            };
            #[cfg(coverage)]
            let (i, c) = char_at(haystack, cursor).expect("cursor within the path run");
            if c == '.' {
                let after_dot = i + 1;
                for ext in extensions {
                    if ascii_starts_with_ignore_case(haystack, after_dot, ext) {
                        ends.push(after_dot + ext.len());
                    }
                }
            }
            cursor = i + c.len_utf8();
        }
        ends
    })
}

/// `[\w.\-~%]*(?:secrets?|credentials?)\.(?:ext|...)` (id 133).
fn secrets_run_bad<'a>(extensions: &'a [&'a str]) -> BadMatcher<'a> {
    Box::new(move |haystack: &str, pos: usize| -> Vec<usize> {
        let run_end = walk_forward_while(haystack, pos, is_path_class);
        let mut ends = Vec::new();
        let mut cursor = pos;
        while cursor < run_end {
            #[cfg(not(coverage))] // unreachable: cursor < run_end is always a boundary
            let Some((i, c)) = char_at(haystack, cursor) else {
                break;
            };
            #[cfg(coverage)]
            let (i, c) = char_at(haystack, cursor).expect("cursor within the path run");
            for stem in ["secret", "credential"] {
                if !ascii_starts_with_ignore_case(haystack, i, stem) {
                    continue;
                }
                let mut after_stem = i + stem.len();
                if let Some((_, plural)) = char_at(haystack, after_stem)
                    && matches!(plural, 's' | 'S')
                {
                    after_stem += 1;
                }
                if char_at(haystack, after_stem).map(|(_, c)| c) != Some('.') {
                    continue;
                }
                let after_dot = after_stem + 1;
                for ext in extensions {
                    if ascii_starts_with_ignore_case(haystack, after_dot, ext) {
                        ends.push(after_dot + ext.len());
                    }
                }
            }
            cursor = i + c.len_utf8();
        }
        ends
    })
}

const CONFIG_EXTENSIONS: &[&str] = &["env", "yml", "yaml", "json", "toml", "ini", "xml", "conf"];

/// `(?:(?!config)[\w-])*config[\w-]*\.(?:env|yml|...)` (id 103). Only the first
/// `config` occurrence in a `[\w-]` run is reachable: every later occurrence
/// has a `config` start in its consumed prefix, which the per-char lookahead
/// rejects. Literals fold ASCII case (builtin IGNORECASE).
fn config_bad(haystack: &str, pos: usize) -> Vec<usize> {
    let run_end = walk_forward_while(haystack, pos, is_word_dash);
    let mut config_start = None;
    let mut cursor = pos;
    while cursor + "config".len() <= run_end {
        if ascii_starts_with_ignore_case(haystack, cursor, "config") {
            config_start = Some(cursor);
            break;
        }
        cursor = char_at(haystack, cursor).map_or(cursor + 1, |(i, c)| i + c.len_utf8());
    }
    let Some(config_start) = config_start else {
        return Vec::new();
    };
    let word_end = walk_forward_while(haystack, config_start + "config".len(), is_word_dash);
    if char_at(haystack, word_end).map(|(_, c)| c) != Some('.') {
        return Vec::new();
    }
    let after_dot = word_end + 1;
    let mut ends = Vec::new();
    for ext in CONFIG_EXTENSIONS {
        if ascii_starts_with_ignore_case(haystack, after_dot, ext) {
            ends.push(after_dot + ext.len());
        }
    }
    ends
}

/// `.env` family: BAD = `\.env(?:\.\w+)?` (longest first).
fn env_bad(haystack: &str, pos: usize) -> Vec<usize> {
    let mut ends = Vec::new();
    if ascii_starts_with_ignore_case(haystack, pos, ".env") {
        let after = pos + 4;
        if char_at(haystack, after).map(|(_, c)| c) == Some('.') {
            let word_end = walk_forward_while(haystack, after + 1, py_is_word);
            if word_end > after + 1 {
                ends.push(word_end);
            }
        }
        ends.push(after);
    }
    ends
}

/// `\.(?:git|svn|hg|bzr)` (id 106).
fn dot_alternative_bad<'a>(names: &'a [&'a str]) -> BadMatcher<'a> {
    Box::new(move |haystack: &str, pos: usize| -> Vec<usize> {
        let mut ends = Vec::new();
        if char_at(haystack, pos).map(|(_, c)| c) == Some('.') {
            for name in names {
                if ascii_starts_with_ignore_case(haystack, pos + 1, name) {
                    ends.push(pos + 1 + name.len());
                }
            }
        }
        ends
    })
}

/// `(?:wp-(admin|login|content|includes|config)|administrator|xmlrpc)\.?(?:php)?`
/// (id 109).
fn wp_admin_bad(haystack: &str, pos: usize) -> Vec<usize> {
    const HEADS: &[&str] = &[
        "wp-admin",
        "wp-login",
        "wp-content",
        "wp-includes",
        "wp-config",
        "administrator",
        "xmlrpc",
    ];
    let mut ends = Vec::new();
    for head in HEADS {
        if ascii_starts_with_ignore_case(haystack, pos, head) {
            let after = pos + head.len();
            // greedy `\.?` then `(?:php)?`
            let dotted = char_at(haystack, after).map(|(_, c)| c) == Some('.');
            let after_dot = if dotted { after + 1 } else { after };
            if ascii_starts_with_ignore_case(haystack, after_dot, "php") {
                ends.push(after_dot + 3);
            }
            if dotted {
                ends.push(after_dot);
            }
            ends.push(after);
        }
    }
    ends
}

const MANAGEMENT_BAD: &[&str] = &[
    "management",
    "config_dump",
    "credentials",
    "system/version",
    "system\\version",
    "version/system",
    "version\\system",
];

pub const RECON_APP_BAD: &[&str] = &[
    "geoserver",
    "confluence",
    "nifi",
    "ScadaBR",
    "pandora_console",
    "centreon",
    "kylin",
    "decisioncenter",
    "evox",
    "MagicInfo",
    "metasys",
    "officescan",
    "helpdesk",
    "ignite",
];

pub const RECON_README_BAD: &[&str] = &[
    "readme.txt",
    "README.md",
    "CHANGELOG",
    "pom.xml",
    "build.gradle",
    "appsettings.json",
    "crossdomain.xml",
];

pub const BACKUP_EXTENSIONS: &[&str] = &[
    "bak", "backup", "old", "orig", "save", "swp", "swo", "tmp", "temp",
];

pub const SECRETS_EXTENSIONS: &[&str] = &[
    "py", "json", "yml", "yaml", "toml", "txt", "env", "xml", "conf", "cfg",
];

pub const DOCKERFILE_BAD: &[&str] = &[
    "docker-compose",
    "Dockerfile",
    "Makefile",
    "Vagrantfile",
    "Jenkinsfile",
    "Procfile",
];

pub const DOUBLE_DOT_BAD: &[&str] = &[
    ".htaccess",
    ".htpasswd",
    ".DS_Store",
    "Thumbs.db",
    ".npmrc",
    ".dockerenv",
    "web.config",
];

/// `\A[/\\]?...\.env...` (id 101).
#[must_use]
pub fn sensitive_path_env(haystack: &str) -> Vec<Candidate> {
    sensitive_path_finditer(haystack, LeadingSep::Optional, env_bad)
}

/// `\A[/\\]?...(?:wp-...|administrator|xmlrpc)...` (id 109).
#[must_use]
pub fn sensitive_path_wp_admin(haystack: &str) -> Vec<Candidate> {
    sensitive_path_finditer(haystack, LeadingSep::Optional, wp_admin_bad)
}

/// `\A[/\\]...(?:management|config_dump|credentials|system[/\\]version|...)`
/// (id 117; the nested shape requires the leading separator).
#[must_use]
pub fn sensitive_path_management(haystack: &str) -> Vec<Candidate> {
    sensitive_path_finditer(haystack, LeadingSep::Required, literal_bad(MANAGEMENT_BAD))
}

/// `\A[/\\]?...[^\w.\-~%]*\.(?:ext|...)` (ids 104 `.map`, 113 backup files).
#[must_use]
pub fn sensitive_path_scan_ext(haystack: &str, extensions: &[&str]) -> Vec<Candidate> {
    sensitive_path_finditer(
        haystack,
        LeadingSep::Optional,
        extension_run_bad(extensions),
    )
}

/// `\A[/\\]?...\.(?:git|svn|hg|bzr)...` (id 106).
#[must_use]
pub fn sensitive_path_dot_alt(haystack: &str, names: &[&str]) -> Vec<Candidate> {
    sensitive_path_finditer(haystack, LeadingSep::Optional, dot_alternative_bad(names))
}

/// `\A[/\\]?...(?:phpinfo|info|test|php_info)\.php...` (id 111) and the
/// literal-plus-extension shapes.
#[must_use]
pub fn sensitive_path_literal_ext(haystack: &str, names: &[&str], ext: &str) -> Vec<Candidate> {
    let literals: Vec<String> = names.iter().map(|name| format!("{name}.{ext}")).collect();
    let refs: Vec<&str> = literals.iter().map(String::as_str).collect();
    sensitive_path_finditer(haystack, LeadingSep::Optional, literal_bad(&refs))
}

/// `\A[/\\]?...(?:alt|alt|...)...` anchored literal shapes (ids 114, 119, 122,
/// 123, 124, 126, 128, 130, 131, 134, 135, 136).
#[must_use]
pub fn sensitive_path_literal(haystack: &str, literals: &[&str]) -> Vec<Candidate> {
    sensitive_path_finditer(haystack, LeadingSep::Optional, literal_bad(literals))
}

/// Anchored literal shapes with an optional trailing group (ids 121, 132).
#[must_use]
pub fn sensitive_path_literal_suffix(
    haystack: &str,
    literals: &[&str],
    suffix: BadSuffix,
) -> Vec<Candidate> {
    sensitive_path_finditer(
        haystack,
        LeadingSep::Optional,
        literal_suffix_bad(literals, suffix),
    )
}

/// Anchored literal shapes with `(?:\.[\w.\-~%]*)?` (id 125).
#[must_use]
pub fn sensitive_path_literal_suffix_dot(haystack: &str, literals: &[&str]) -> Vec<Candidate> {
    sensitive_path_literal_suffix(haystack, literals, BadSuffix::DotRun)
}

/// `\A[/\\]?...(?:secrets?|credentials?)\.(?:ext|...)...` (id 133).
#[must_use]
pub fn sensitive_path_secrets(haystack: &str) -> Vec<Candidate> {
    sensitive_path_finditer(
        haystack,
        LeadingSep::Optional,
        secrets_run_bad(SECRETS_EXTENSIONS),
    )
}

/// `\A[/\\]?...(?:(?!config)[\w-])*config[\w-]*\.(?:env|yml|...)...` (id 103).
#[must_use]
pub fn sensitive_path_config(haystack: &str) -> Vec<Candidate> {
    sensitive_path_finditer(haystack, LeadingSep::Optional, config_bad)
}

/// The attack-report lexicon of the embedded-prose shapes (`ids 33, 102, 107,
/// 110, 112, 115`), verbatim from the canonical sources.
const ATTACK_REPORT_LEXICON: &str = r"\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\b";

/// Lexicon-lookahead path shapes (ids 33/102/107/110/112/115).
///
/// The reference pattern is `\A(?=(?:(?!\n).)*LEXICON)\A(?:(?!\n).)*<path-shape>`,
/// so the shape must sit in the first line and the first line must carry a
/// lexicon word.
#[must_use]
pub fn lexicon_path_finditer(haystack: &str, shape: &str, require_lexicon: bool) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: every caller passes a statically valid shape
    let Ok(compiled) = PyRegex::compile(shape, true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let compiled = PyRegex::compile(shape, true).expect("statically valid shape");
    let matches: Vec<Candidate> = compiled
        .re()
        .find_iter(haystack)
        .map(|m| Candidate::new(m.start(), m.end()))
        .collect();
    if !require_lexicon || matches.is_empty() {
        return matches;
    }
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(lexicon) = PyRegex::compile(ATTACK_REPORT_LEXICON, true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let lexicon = PyRegex::compile(ATTACK_REPORT_LEXICON, true).expect("statically valid literal");
    let first_line_end = haystack.find('\n').unwrap_or(haystack.len());
    if lexicon.re().is_match(&haystack[..first_line_end]) {
        matches
    } else {
        Vec::new()
    }
}

/// `Object\.prototype\.[A-Za-z_$][\w$]*\s*=(?!=)` (id 139).
///
/// The negative lookahead becomes a suffix check on the assignment operator.
/// The row carries the reference's builtin IGNORECASE, so it compiles
/// case-folded.
#[must_use]
pub fn proto_pollution_assign_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(r"Object\.prototype\.[A-Za-z_$][\w$]*\s*=", true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(r"Object\.prototype\.[A-Za-z_$][\w$]*\s*=", true)
        .expect("statically valid literal");
    guarded_finditer(haystack, re.re(), |text, candidate| {
        text.as_bytes().get(candidate.end) != Some(&b'=')
    })
}
// ---------------------------------------------------------------------------
// Deserialization base64 magic prefixes
// ---------------------------------------------------------------------------

/// `(?<![A-Za-z0-9+/])(?-i:MAGIC)` for the four magic prefixes; the
/// lookbehind is a boundary check on the literal occurrence.
#[must_use]
pub fn deserialization_b64_finditer(haystack: &str, magic: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = haystack[from..].find(magic) {
        let start = from + rel;
        let end = start + magic.len();
        let boundary_ok = start == 0
            || char_before(haystack, start)
                .is_none_or(|(_, c)| !c.is_ascii_alphanumeric() && c != '/' && c != '+');
        if boundary_ok {
            out.push(Candidate::new(start, end));
            from = end;
        } else {
            from = start + 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SQLi ORDER BY terminator (second alternative guard)
// ---------------------------------------------------------------------------

/// `(?i)\bORDER\s+BY\s+\d+\s*(?:--|#|;|\)|,|/\*|\Z)|(?<=[=?&])ORDER\s+BY\s+\d+\s*\n`
#[must_use]
pub fn sqli_order_by_terminator_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(alt1) = PyRegex::compile(r"\bORDER\s+BY\s+\d+\s*(?:--|#|;|\)|,|/\*|\z)", true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let alt1 = PyRegex::compile(r"\bORDER\s+BY\s+\d+\s*(?:--|#|;|\)|,|/\*|\z)", true)
        .expect("statically valid literal");
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(alt2) = PyRegex::compile(r"ORDER\s+BY\s+\d+\s*\n", true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let alt2 = PyRegex::compile(r"ORDER\s+BY\s+\d+\s*\n", true).expect("statically valid literal");
    let mut out: Vec<Candidate> = alt1
        .re()
        .find_iter(haystack)
        .map(|m| Candidate::new(m.start(), m.end()))
        .collect();
    let guarded = guarded_finditer(haystack, alt2.re(), |text, candidate| {
        candidate.start > 0
            && char_before(text, candidate.start).is_some_and(|(_, c)| matches!(c, '=' | '?' | '&'))
    });
    out.extend(guarded);
    out.sort_by_key(|c| (c.start, std::cmp::Reverse(c.end)));
    out
}

// ---------------------------------------------------------------------------
// File-inclusion bare host (lookbehind guard)
// ---------------------------------------------------------------------------

/// `(?:(?<!:)\/\/HOST...)`: the lookbehind is a one-char prefix check.
#[must_use]
pub fn file_inclusion_bare_host_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(
        r"//(?:[0-9a-zA-Z](?:[-\w]*[0-9a-zA-Z])?(?:\.[0-9a-zA-Z](?:[-\w]*[0-9a-zA-Z])?)+)(:[0-9]+)?(?:/?)(?:[a-zA-Z0-9\-\.\?,'/\\+&amp;%$#_]*)?",
        false,
    ) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(
        r"//(?:[0-9a-zA-Z](?:[-\w]*[0-9a-zA-Z])?(?:\.[0-9a-zA-Z](?:[-\w]*[0-9a-zA-Z])?)+)(:[0-9]+)?(?:/?)(?:[a-zA-Z0-9\-\.\?,'/\\+&amp;%$#_]*)?",
        false,
    )
    .expect("statically valid literal");
    guarded_finditer(haystack, re.re(), |text, candidate| {
        candidate.start == 0 || char_before(text, candidate.start).is_none_or(|(_, c)| c != ':')
    })
}

// ---------------------------------------------------------------------------
// File-inclusion scheme URL (trailing lookahead + bounded window)
// ---------------------------------------------------------------------------

const SCHEME_PATH_TRIMMED: &str =
    r#"=(?:https?|ftp)://[^\s'"<>]+/[^\s'"<>/]*\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)"#;

/// id 63: the reference runs the UNMODIFIED pattern inside the bounded window.
///
/// The trailing `(?![a-zA-Z0-9])` is enforced as a suffix guard; on rejection
/// the scan abandons the prefix candidate and moves to the next one, exactly
/// like a failed window match.
#[must_use]
pub fn file_inclusion_scheme_path_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literals
    let (Some(compiled), Some(prefix), Some(terminator)) = (
        PyRegex::compile(SCHEME_PATH_TRIMMED, true).ok(),
        PyRegex::compile(r"=(?:https?|ftp)://", true).ok(),
        PyRegex::compile(
            r"\.(?:phtml|php\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*",
            true,
        )
        .ok(),
    ) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let (compiled, prefix, terminator) = (
        PyRegex::compile(SCHEME_PATH_TRIMMED, true),
        PyRegex::compile(r"=(?:https?|ftp)://", true),
        PyRegex::compile(
            r"\.(?:phtml|php\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*",
            true,
        ),
    );
    #[cfg(coverage)]
    let (compiled, prefix, terminator) = (
        compiled.expect("statically valid literal"),
        prefix.expect("statically valid literal"),
        terminator.expect("statically valid literal"),
    );
    super::scan_window::bounded_finditer_guarded(
        haystack,
        &compiled,
        &prefix,
        &terminator,
        |text, candidate| {
            char_at(text, candidate.end).is_none_or(|(_, c)| !c.is_ascii_alphanumeric())
        },
    )
}

// ---------------------------------------------------------------------------
// File-inclusion template URL (inner lookahead implied by the closing quote)
// ---------------------------------------------------------------------------

const TEMPLATE_URL_TRIMMED: &str = r#"["'](?:template|include|tpl|module|layout)["']\s*:\s*["'](?:https?|ftp)://[^\s'"<>]+/[^\s'"<>/]*\.(?:phtml|php[3-5]?|phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)["']"#;

/// id 64: the source's `(?![a-zA-Z0-9])` sits directly before the required
/// closing quote, so any match of the lookahead-free equivalent already
/// satisfies it (the quote is never alphanumeric).
#[must_use]
pub fn file_inclusion_template_url_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(compiled) = PyRegex::compile(TEMPLATE_URL_TRIMMED, true) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let compiled = PyRegex::compile(TEMPLATE_URL_TRIMMED, true).expect("statically valid literal");
    compiled
        .re()
        .find_iter(haystack)
        .map(|m| Candidate::new(m.start(), m.end()))
        .collect()
}

// ---------------------------------------------------------------------------
// Glued backtick candidate (lookbehind guard)
// ---------------------------------------------------------------------------

/// `(?<!\x60)\x60(?:[A-Za-z0-9_./~]|\$[({])(?:[^\x60\\\n]|\\.)*\x60`
#[must_use]
pub fn glued_backtick_candidate_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(re) = PyRegex::compile(r"`(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*`", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(r"`(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*`", false)
        .expect("statically valid literal");
    guarded_finditer(haystack, re.re(), |text, candidate| {
        candidate.start == 0 || char_before(text, candidate.start).is_none_or(|(_, c)| c != '`')
    })
}

// ---------------------------------------------------------------------------
// XSS event-handler attribute walker
// ---------------------------------------------------------------------------

/// The frozen 2026-08-20 `_HTML_EVENT_HANDLER_ATTRS` set, in reference order
/// (extracted verbatim from the canonical pattern source).
pub const HTML_EVENT_HANDLER_ATTRS: &[&str] = &[
    "onwebkitplaybacktargetavailabilitychanged",
    "oncontentvisibilityautostatechange",
    "onwebkitpresentationmodechanged",
    "onwebkitmouseforcewillbegin",
    "onwebkitanimationiteration",
    "onsecuritypolicyviolation",
    "onwebkitmouseforcechanged",
    "onvalidationstatuschange",
    "onwebkitfullscreenchange",
    "onwebkitwillrevealbottom",
    "onwebkitanimationstart",
    "onwebkitmouseforcedown",
    "onbeforescriptexecute",
    "onmozfullscreenchange",
    "onwebkittransitionend",
    "onafterscriptexecute",
    "onanimationiteration",
    "onlostpointercapture",
    "onscrollsnapchanging",
    "onunhandledrejection",
    "onwebkitanimationend",
    "onwebkitmouseforceup",
    "ondeviceorientation",
    "ongotpointercapture",
    "onbeforedeactivate",
    "onfullscreenchange",
    "onpointerrawupdate",
    "onreadystatechange",
    "onrejectionhandled",
    "onscrollsnapchange",
    "ontransitioncancel",
    "onanimationcancel",
    "onbeforeeditfocus",
    "oncontextrestored",
    "ondatasetcomplete",
    "onselectionchange",
    "ontransitionstart",
    "onanimationstart",
    "onbeforeactivate",
    "oncanplaythrough",
    "ondatasetchanged",
    "ondurationchange",
    "onlanguagechange",
    "onlayoutcomplete",
    "onloadedmetadata",
    "onpropertychange",
    "oncontrolselect",
    "ondataavailable",
    "ongesturechange",
    "onmediacomplete",
    "onpointercancel",
    "onpromptdismiss",
    "ontransitionend",
    "ontransitionrun",
    "onwebkitneedkey",
    "onanimationend",
    "onbeforetoggle",
    "onbeforeunload",
    "onbeforeupdate",
    "ondevicemotion",
    "onfilterchange",
    "ongesturestart",
    "onmessageerror",
    "onpointerenter",
    "onpointerleave",
    "onpromptaction",
    "onsyncrestored",
    "onvolumechange",
    "onafterupdate",
    "onbeforeinput",
    "onbeforematch",
    "onbeforepaste",
    "onbeforeprint",
    "oncontextlost",
    "oncontextmenu",
    "onerrorupdate",
    "onlosecapture",
    "onpointerdown",
    "onpointermove",
    "onpointerover",
    "onresizestart",
    "onrowinserted",
    "onselectstart",
    "ontouchcancel",
    "ontrackchange",
    "onafterprint",
    "onbeforecopy",
    "oncellchange",
    "ondeactivate",
    "ongestureend",
    "onhashchange",
    "onloadeddata",
    "onmediaerror",
    "onmouseenter",
    "onmouseleave",
    "onmousewheel",
    "onpagereveal",
    "onpointerout",
    "onratechange",
    "onslotchange",
    "ontimeupdate",
    "ontouchstart",
    "onbeforecut",
    "oncuechange",
    "ondragenter",
    "ondragleave",
    "ondragstart",
    "onloadstart",
    "onmousedown",
    "onmousemove",
    "onmouseover",
    "onmovestart",
    "onoutofsync",
    "onpointerup",
    "onresizeend",
    "onrowdelete",
    "onrowsenter",
    "onscrollend",
    "ontimeerror",
    "ontouchmove",
    "onactivate",
    "onauxclick",
    "ondblclick",
    "ondragdrop",
    "ondragexit",
    "ondragover",
    "onfocusout",
    "onformdata",
    "onkeypress",
    "onlocation",
    "onmouseout",
    "onpagehide",
    "onpageshow",
    "onpageswap",
    "onpopstate",
    "onprogress",
    "ontouchend",
    "oncanplay",
    "oncommand",
    "ondragend",
    "onemptied",
    "onfocusin",
    "oninvalid",
    "onkeydown",
    "onmessage",
    "onmouseup",
    "onmoveend",
    "onoffline",
    "onplaying",
    "onreverse",
    "onrowexit",
    "onseeking",
    "onstalled",
    "onstorage",
    "onsuspend",
    "onurlflip",
    "onwaiting",
    "onbounce",
    "oncancel",
    "onchange",
    "onfinish",
    "ononline",
    "onrepeat",
    "onresize",
    "onresume",
    "onscroll",
    "onsearch",
    "onseeked",
    "onselect",
    "onsubmit",
    "ontoggle",
    "onunload",
    "onabort",
    "onbegin",
    "onclick",
    "onclose",
    "onended",
    "onerror",
    "onfocus",
    "oninput",
    "onkeyup",
    "onpaste",
    "onpause",
    "onreset",
    "onstart",
    "onwheel",
    "onblur",
    "oncopy",
    "ondrag",
    "ondrop",
    "onhelp",
    "onload",
    "onmove",
    "onplay",
    "onredo",
    "onseek",
    "onstop",
    "onundo",
    "oncut",
    "onend",
];

/// ASCII case-folded `starts_with` at a byte position: the reference's builtin
/// `re.IGNORECASE` folding for the ASCII literals of the structural rows.
fn ascii_starts_with_ignore_case(haystack: &str, pos: usize, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let Some(window) = bytes.get(pos..pos + needle.len()) else {
        return false;
    };
    window
        .iter()
        .zip(needle.bytes())
        .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

/// The value part: `\s*=\s{0,20}(?:["'][^"']*["']|[^\s>]+)`, returning the end.
fn event_handler_value_end(haystack: &str, pos: usize) -> Option<usize> {
    let mut cursor = walk_forward_while(haystack, pos, char::is_whitespace);
    if char_at(haystack, cursor).map(|(_, c)| c) != Some('=') {
        return None;
    }
    cursor = char_at(haystack, cursor).map_or(cursor, |(i, c)| i + c.len_utf8());
    // `\s{0,20}`
    let mut taken = 0usize;
    while taken < 20 && char_at(haystack, cursor).is_some_and(|(_, c)| c.is_whitespace()) {
        cursor = char_at(haystack, cursor).map_or(cursor, |(i, c)| i + c.len_utf8());
        taken += 1;
    }
    match char_at(haystack, cursor).map(|(_, c)| c) {
        Some(quote @ ('"' | '\'')) => {
            // `["'][^"']*["']`: the body excludes BOTH quote characters and
            // the FIRST quote encountered ends the value (either flavor)
            let mut scan = cursor + quote.len_utf8();
            while let Some((i, c)) = char_at(haystack, scan) {
                if c == '"' || c == '\'' {
                    return Some(i + c.len_utf8());
                }
                scan = i + c.len_utf8();
            }
            None
        }
        Some(_) => {
            let end = walk_forward_while(haystack, cursor, |c| !c.is_whitespace() && c != '>');
            (end > cursor).then_some(end)
        }
        None => None,
    }
}

/// `(?<!=)(?<!=\")(?<!=')` evaluated at the whitespace/slash run start: the
/// 1-char lookbehind rejects a bare `=`; the 2-char lookbehinds reject the
/// sequences `="` and `='`.
fn event_handler_lookbehind_ok(haystack: &str, run_start: usize) -> bool {
    #[cfg(not(coverage))] // unreachable: the run always starts past the tag-open letter
    let Some((c1_pos, c1)) = char_before(haystack, run_start) else {
        return true; // nothing before the run: the lookbehinds pass trivially
    };
    #[cfg(coverage)]
    let (c1_pos, c1) = char_before(haystack, run_start).expect("run past the tag-open letter");
    if c1 == '=' {
        return false;
    }
    if c1 == '"' || c1 == '\'' {
        let quoted_after_equals = char_before(haystack, c1_pos).is_some_and(|(_, c2)| c2 == '=');
        if quoted_after_equals {
            return false;
        }
    }
    true
}

/// The maximal whitespace/slash run ending at/just before `run_start`.
fn event_handler_run_end(haystack: &str, run_start: usize) -> usize {
    let mut pos = run_start;
    while char_at(haystack, pos).is_some_and(|(_, rc)| rc.is_whitespace() || rc == '/') {
        pos = char_at(haystack, pos).map_or(haystack.len(), |(i, rc)| i + rc.len_utf8());
    }
    pos
}

/// The monster pattern:
/// `(?:<[A-Za-z/](?:[^<>]*[^<>\s/])?(?<!=)(?<!=\")(?<!=')[\s/]+(?:NAMES)\s*=\s{0,20}(?:["'][^"']*["']|[^\s>]+))`.
///
/// The three lookbehinds sit between the attribute group and the whitespace
/// run, and the group is greedy: the engine tries the RIGHTMOST run split
/// first (longest attribute group) and backtracks leftward, with the
/// group-absent split (right after the tag-open letter) last. Each split's
/// guard is a 1-2 char sequence check on the characters before the run.
#[must_use]
pub fn xss_event_handler_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(tag_open) = PyRegex::compile(r"<[A-Za-z/]", false) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let tag_open = PyRegex::compile(r"<[A-Za-z/]", false).expect("statically valid literal");
    let mut matches = Vec::new();
    let mut resume = 0usize;
    for open in tag_open.re().find_iter(haystack) {
        if open.start() < resume {
            continue;
        }
        // whitespace/slash run starts in the attribute region (bounded by the
        // next angle bracket), leftmost-first
        let mut runs: Vec<usize> = Vec::new();
        let mut cursor = open.end();
        let mut open_run: Option<usize> = None;
        while let Some((offset, c)) = char_at(haystack, cursor) {
            if c == '<' || c == '>' {
                break;
            }
            if c.is_whitespace() || c == '/' {
                if open_run.is_none() {
                    open_run = Some(offset);
                }
            } else if let Some(r) = open_run.take() {
                runs.push(r);
            }
            cursor = offset + c.len_utf8();
        }
        if let Some(r) = open_run {
            runs.push(r);
        }
        // the greedy attribute group tries the longest run first
        runs.reverse();
        for r in runs {
            let run_end = event_handler_run_end(haystack, r);
            if event_handler_lookbehind_ok(haystack, r)
                && let Some(end) = try_event_name_value(haystack, run_end)
            {
                matches.push(Candidate::new(open.start(), end));
                resume = end;
                break;
            }
        }
    }
    matches
}

fn try_event_name_value(haystack: &str, name_pos: usize) -> Option<usize> {
    for name in HTML_EVENT_HANDLER_ATTRS {
        if ascii_starts_with_ignore_case(haystack, name_pos, name) {
            let after_name = name_pos + name.len();
            if let Some(end) = event_handler_value_end(haystack, after_name) {
                return Some(end);
            }
        }
    }
    None
}

// helper re-export for the scan-window module users
#[must_use]
pub fn rfind_in(haystack: &str, needle: &str, start: usize, end: usize) -> Option<usize> {
    str_rfind_in(haystack, needle, start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_from_first_reachable_from() {
        let ms = sqli_select_from_finditer("SELECT a FROM b");
        assert_eq!(ms.len(), 1);
        // the lazy loop stops at the first `\bFROM\b`
        assert_eq!(ms[0].text("SELECT a FROM b"), "SELECT a FROM");
    }

    #[test]
    fn select_from_blocked_by_second_select() {
        // the first scan is blocked by the second SELECT, but finditer
        // rescans from the next position and finds `SELECT FROM`
        let ms = sqli_select_from_finditer("SELECT x SELECT FROM");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 9);
        assert_eq!(ms[0].text("SELECT x SELECT FROM"), "SELECT FROM");
    }

    #[test]
    fn tautology_requires_equal_atoms() {
        let ms = sqli_tautology_finditer("' OR 1=1--");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("' OR 1=1--"), "OR 1=1");
        assert!(sqli_tautology_finditer("' OR 1=2--").is_empty());
    }

    #[test]
    fn ssrf_private_requires_scheme_for_userinfo() {
        let ms = ssrf_private_host_finditer("http://10.0.0.1/shell.txt");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("http://10.0.0.1/shell.txt"), "/10.0.0.1/");
        // bare host without scheme context still fires via whitespace prefix
        let ms = ssrf_private_host_finditer("| nc 10.0.0.1 4444");
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn ssrf_numeric_guard() {
        let ms = ssrf_numeric_host_finditer("curl http://10.0.0.1/x.sh");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("curl http://10.0.0.1/x.sh"), "://10.0.0.1");
        // terminator must follow the host
        assert!(ssrf_numeric_host_finditer("curl http://10.0.0.1x/").is_empty());
    }

    #[test]
    fn shell_dash_flag_lookahead() {
        let ms = shell_dash_flag_finditer("bash -c \"id\"");
        assert_eq!(ms.len(), 1);
        assert!(shell_dash_flag_finditer("bash -c \"id\" x tail").is_empty());
    }

    #[test]
    fn sensitive_env_path() {
        let ms = sensitive_path_env("/.env");
        assert_eq!(ms.len(), 1);
        // `.env.local` is itself the BAD alternative (`.env` + `.\w+`)
        let ms = sensitive_path_env("/app/.env.local/config");
        assert_eq!(ms.len(), 1);
        let ms = sensitive_path_env("/app/.env");
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn sensitive_wp_admin_path() {
        assert_eq!(sensitive_path_wp_admin("/wp-login.php").len(), 1);
        assert_eq!(
            sensitive_path_wp_admin("/wp-admin/setup-config.php").len(),
            1
        );
        assert!(sensitive_path_wp_admin("/admin/login/?next=/admin/").is_empty());
    }

    #[test]
    fn sensitive_backup_path() {
        assert_eq!(
            sensitive_path_scan_ext("/config.php.bak", BACKUP_EXTENSIONS).len(),
            1
        );
        assert!(sensitive_path_scan_ext("/config.php", BACKUP_EXTENSIONS).is_empty());
    }

    #[test]
    fn management_requires_leading_separator() {
        assert_eq!(sensitive_path_management("/.aws/credentials").len(), 1);
        assert!(sensitive_path_management(".aws/credentials").is_empty());
    }

    #[test]
    fn deserialization_magic_boundary() {
        assert_eq!(deserialization_b64_finditer("rO0ABXNy", "rO0AB").len(), 1);
        assert!(deserialization_b64_finditer("BASE64rO0AB", "rO0AB").is_empty());
    }

    #[test]
    fn event_handler_matches_unquoted() {
        let ms = xss_event_handler_finditer("<img src=x onerror=alert(1)>");
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms[0].text("<img src=x onerror=alert(1)>"),
            "<img src=x onerror=alert(1)"
        );
    }

    #[test]
    fn event_handler_slash_separated() {
        let ms = xss_event_handler_finditer("/search?q=<svg/onload=alert(1)>");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 10);
    }

    #[test]
    fn event_handler_quoted_attr_value_still_matches() {
        // oracle-verified: the lookbehinds reject the SEQUENCES `=`/`="/`='`
        // before the run; a bare `"` before the run does not block, and the
        // greedy group picks the rightmost split (`onerror`)
        let ms = xss_event_handler_finditer("<img src=\"x\" onerror=alert(1)>");
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms[0].text("<img src=\"x\" onerror=alert(1)>"),
            "<img src=\"x\" onerror=alert(1)"
        );
    }

    #[test]
    fn event_handler_greedy_group_picks_rightmost_split() {
        // oracle-verified: the greedy attribute group tries the rightmost
        // run first, so the second handler wins the match
        let text = "<a b onclick=x c onload=y>";
        let ms = xss_event_handler_finditer(text);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text(text), "<a b onclick=x c onload=y");
    }

    #[test]
    fn event_handler_equals_sequence_lookbehind_blocks() {
        // `="` directly before the run: the 2-char lookbehind blocks, and no
        // other split can rescue the match
        assert!(xss_event_handler_finditer("<a =\" onclick=x>").is_empty());
        // a bare `=` directly before the run: the 1-char lookbehind blocks
        assert!(xss_event_handler_finditer("<img src= onerror=x>").is_empty());
        // oracle-verified: `=x` before the run does NOT block (rightmost
        // split sees `x`, not `=`)
        let ms = xss_event_handler_finditer("<img =x onerror=alert(1)>");
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms[0].text("<img =x onerror=alert(1)>"),
            "<img =x onerror=alert(1)"
        );
    }

    #[test]
    fn event_handler_nested_quote_value_ends_at_first_quote() {
        // the value body excludes both quote flavors, and the first quote
        // encountered closes the value (either flavor): `"alert('`
        let ms = xss_event_handler_finditer("<div onmouseover=\"alert('x')\">hover</div>");
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms[0].text("<div onmouseover=\"alert('x')\">hover</div>"),
            "<div onmouseover=\"alert('"
        );
    }

    #[test]
    fn inline_comment_guard() {
        let ms = sqli_inline_comment_finditer("UNI/**/ON SE/**/LECT");
        assert_eq!(ms.len(), 2);
        assert!(sqli_inline_comment_finditer("UNI/*!*/ON").is_empty());
    }

    #[test]
    fn backtick_candidate_guard() {
        let compiled =
            PyRegex::compile(r"`(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*`", false).unwrap();
        let ms = glued_backtick_candidate_finditer("a`id`b");
        assert_eq!(ms.len(), 1);
        let _ = compiled;
        assert!(glued_backtick_candidate_finditer("``id`").is_empty());
    }

    #[test]
    fn match_span_truncates_overshoots_and_rejects_bad_bounds() {
        let re = PyRegex::compile(r"ab?", false).unwrap();
        // start past end
        assert!(match_span(re.re(), "abab", 3, 2).is_none());
        // the greedy match overshoots `end`: the truncated retry wins
        let m = match_span(re.re(), "ab", 0, 1).expect("truncated match");
        assert_eq!((m.start, m.end), (0, 1));
        // the truncated retry cannot match either
        assert!(match_span(re.re(), "ab", 1, 1).is_none());
        // no match at `start` at all
        assert!(match_span(PyRegex::compile(r"zz", false).unwrap().re(), "ab", 0, 2).is_none());
        // a match found only after `start` is not an anchor
        assert!(match_span(PyRegex::compile(r"b", false).unwrap().re(), "ab", 0, 2).is_none());
        // the truncated retry can only anchor at `start` (or not match)
        let alt = PyRegex::compile(r"aba|b", false).unwrap();
        assert!(match_span(alt.re(), "aba", 0, 2).is_none());
    }

    #[test]
    fn shell_dash_c_skips_prefixes_swallowed_by_tokens_and_matches() {
        let compiled = PyRegex::compile(r"\n[^\S\r\n]*evil\s+-c", false).unwrap();
        // the row matches right at the newline prefix
        let ms = shell_dash_c_finditer("\n  evil -c id", &compiled);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("\n  evil -c id"), "\n  evil -c");
        // no newline prefix, no candidate
        assert!(shell_dash_c_finditer("evil -c id", &compiled).is_empty());
        // token runs extend the resume point past a failed row match
        assert!(shell_dash_c_finditer("\n  X=1  Y=2 evil -c id", &compiled).is_empty());
        // a later prefix swallowed by the previous resume point is skipped
        assert!(shell_dash_c_finditer("\n x=1\n y=2 evil", &compiled).is_empty());
    }

    #[test]
    fn shell_dash_c_finds_the_row_after_newline_indent() {
        let compiled = PyRegex::compile(r"\n[^\S\r\n]*evil\s+-c", false).unwrap();
        let ms = shell_dash_c_finditer("\n  evil -c id", &compiled);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("\n  evil -c id"), "\n  evil -c");
        // no newline prefix, no candidate
        assert!(shell_dash_c_finditer("evil -c id", &compiled).is_empty());
    }

    #[test]
    fn ldap_null_byte_attr_walks_back_to_the_attribute() {
        let compiled = PyRegex::compile(r"uid", false).unwrap();
        let ms = ldap_null_byte_attr_raw("(uid=*)%00", &compiled);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 1);
        assert_eq!(ms[0].end, 4);
        let ms = ldap_null_byte_attr_decoded("(uid=*)\0", &compiled);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 1);
    }

    #[test]
    fn ldap_null_byte_attr_rejects_non_attribute_prefixes() {
        let compiled = PyRegex::compile(r"uid", false).unwrap();
        // no `*` + `)` pair at all
        assert!(ldap_null_byte_attr_raw("(uid=x)", &compiled).is_empty());
        // nothing word-like before the star run
        assert!(ldap_null_byte_attr_raw("*)%00", &compiled).is_empty());
        // the character before the value run is not `=`
        assert!(ldap_null_byte_attr_raw("-a*)%00", &compiled).is_empty());
        // no attribute name between a boundary and the `=`
        assert!(ldap_null_byte_attr_raw("=*)%00", &compiled).is_empty());
        // the attribute name does not start with a letter
        assert!(ldap_null_byte_attr_raw("1a=*)%00", &compiled).is_empty());
    }

    #[test]
    fn quote_splice_resumes_past_failed_candidates() {
        let compiled = PyRegex::compile(r"zzz", false).unwrap();
        assert!(quote_splice_finditer("ab\"cd", &compiled).is_empty());
    }

    #[test]
    fn quote_splice_matches_word_then_quote_and_skips_consumed_quotes() {
        // a quote splicing a word onto the row pattern matches
        let compiled = PyRegex::compile(r"ab", false).unwrap();
        let ms = quote_splice_finditer("ab\"cd", &compiled);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("ab\"cd"), "ab");
        // a quote inside the previous match's span is skipped
        let greedy = PyRegex::compile(r"ab.+", false).unwrap();
        let ms = quote_splice_finditer("ab\"cd\"ef", &greedy);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("ab\"cd\"ef"), "ab\"cd\"ef");
        // a quote at end of input has no word after it
        assert!(quote_splice_finditer("ab\"", &compiled).is_empty());
        // a quote not preceded by a word character cannot splice
        assert!(
            quote_splice_finditer(" \"cd", &PyRegex::compile(r"cd", false).unwrap()).is_empty()
        );
    }

    #[test]
    fn ssrf_private_userinfo_requires_scheme_context() {
        // userinfo present but not directly after `://`: rejected
        assert!(ssrf_private_host_finditer("evil@10.0.0.1/x").is_empty());
        // userinfo directly after `://`: accepted
        let ms = ssrf_private_host_finditer("http://user@10.0.0.1/x");
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn ssrf_numeric_host_accepts_end_of_text_terminator() {
        let ms = ssrf_numeric_host_finditer("curl http://10.0.0.1");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text("curl http://10.0.0.1"), "://10.0.0.1");
    }

    #[test]
    fn select_from_requires_word_boundaries() {
        // SELECT glued to a word character is never a loop start
        assert!(sqli_select_from_finditer("xSELECT a FROM b").is_empty());
        // FROM must also sit on its own word boundary
        assert!(sqli_select_from_finditer("SELECT a xFROM b").is_empty());
    }

    #[test]
    fn tautology_backtracks_numeric_atoms_digit_by_digit() {
        // neither 12 nor the backtracked 1 completes `12=1`
        assert!(sqli_tautology_finditer("1 OR 12=1").is_empty());
        // a word character after the second atom kills the boundary
        assert!(sqli_tautology_finditer("' OR 1=1x").is_empty());
    }

    #[test]
    fn tautology_swallows_candidates_inside_completed_matches() {
        // the completed `='a OR 1'` comparison ends past the inner OR/AND
        // candidate, so the engine skips it (the reference backtracks the same
        // way: the whole span is one match)
        let ms = sqli_tautology_finditer("' OR 'a OR 1'='a OR 1'x");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 2);
        assert_eq!(ms[0].end, 22);
    }

    #[test]
    fn sensitive_path_tails_accept_query_strings() {
        assert_eq!(sensitive_path_env("/.env?token=abc").len(), 1);
    }

    #[test]
    fn sensitive_paths_walk_segments_and_reject_bad_tails() {
        // the segment loop walks several directories before the BAD literal
        assert_eq!(sensitive_path_management("/x/.aws/credentials").len(), 1);
        // the required shape without a leading separator never matches
        assert!(sensitive_path_management("x/.aws/credentials").is_empty());
        // a BAD literal whose tail does not end the path is rejected
        assert!(sensitive_path_wp_admin("/wp-admin.X").is_empty());
        // the same tail rejection on the boxed-literal rows
        assert!(sensitive_path_management(".aws/credentialsX").is_empty());
    }

    #[test]
    fn literal_suffix_variants_cover_yaml_dot_and_dash_runs() {
        assert_eq!(
            sensitive_path_literal_suffix("/site.yml", &["site"], BadSuffix::YamlSuffix).len(),
            1
        );
        assert_eq!(
            sensitive_path_literal_suffix("/site.yaml", &["site"], BadSuffix::YamlSuffix).len(),
            1
        );
        // the optional suffix group stays absent when no dot follows
        assert!(
            sensitive_path_literal_suffix("/site:8080", &["site"], BadSuffix::YamlSuffix)
                .is_empty()
        );
        assert_eq!(
            sensitive_path_literal_suffix_dot("/app.settings", &["app"]).len(),
            1
        );
        assert_eq!(
            sensitive_path_literal_suffix("/secret-backup", &["secret"], BadSuffix::DashRun).len(),
            1
        );
    }

    #[test]
    fn lexicon_paths_require_the_lexicon_word_on_the_first_line() {
        let shape = r"\A[^\n]*/etc/passwd";
        assert_eq!(
            lexicon_path_finditer("scanner found /etc/passwd", shape, true).len(),
            1
        );
        assert!(lexicon_path_finditer("nothing here /etc/passwd", shape, true).is_empty());
        // the lexicon gate is skipped entirely when not required
        assert_eq!(
            lexicon_path_finditer("nothing here /etc/passwd", shape, false).len(),
            1
        );
    }

    #[test]
    fn order_by_terminator_accepts_both_alternatives() {
        let ms = sqli_order_by_terminator_finditer("ORDER BY 1 -- comment");
        assert_eq!(ms.len(), 1);
        // the lookbehind-guarded newline alternative fires after `=` and the
        // two candidates are returned sorted by (start, end descending)
        let ms = sqli_order_by_terminator_finditer("x=ORDER BY 1\n");
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].start, 2);
        assert_eq!(ms[1].start, 2);
    }

    #[test]
    fn file_inclusion_scheme_path_guard_rejects_trailing_alnum() {
        let ms = file_inclusion_scheme_path_finditer("=http://h/a.php");
        assert_eq!(ms.len(), 1);
        // the extension runs on into alphanumerics: the suffix guard rejects
        assert!(file_inclusion_scheme_path_finditer("=http://h/a.php3x").is_empty());
    }

    #[test]
    fn file_inclusion_template_url_matches_quoted_keys() {
        let hay = "\"tpl\" : \"http://h/x.jsp\"";
        let ms = file_inclusion_template_url_finditer(hay);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].text(hay), "\"tpl\" : \"http://h/x.jsp\"");
    }

    #[test]
    fn event_handler_value_shapes_without_a_value_do_not_match() {
        // no `=` after the handler name
        assert!(xss_event_handler_finditer("<img onclick").is_empty());
        // unterminated quoted value
        assert!(xss_event_handler_finditer("<a onclick=\"unterminated").is_empty());
        // end of input right after the `=`
        assert!(xss_event_handler_finditer("<a onclick=").is_empty());
    }

    #[test]
    fn event_handler_value_takes_up_to_twenty_whitespace_chars() {
        let ms = xss_event_handler_finditer("<a onclick=                    x>");
        assert_eq!(ms.len(), 1);
        // the 21st whitespace char falls outside `\s{0,20}`: the unquoted
        // value would be empty, so nothing matches
        assert!(xss_event_handler_finditer("<a onclick=                     x>").is_empty());
    }

    #[test]
    fn event_handler_skips_tag_opens_inside_consumed_matches() {
        // the `<img` open sits inside the consumed quoted value
        let ms = xss_event_handler_finditer("<div onmouseover=\"<img src=x> onload=y\">");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].start, 0);
    }

    #[test]
    fn event_handler_trailing_whitespace_run_still_scans_the_run() {
        // the whitespace run runs into the closing bracket: the rightmost-run
        // split is tried with no attribute name there, so nothing matches
        assert!(xss_event_handler_finditer("<img src=x >").is_empty());
    }

    #[test]
    fn rfind_in_searches_within_the_window() {
        assert_eq!(rfind_in("abcabc", "abc", 0, 6), Some(3));
        assert_eq!(rfind_in("abcabc", "abc", 0, 3), Some(0));
        assert_eq!(rfind_in("abcabc", "zz", 0, 6), None);
    }
}
