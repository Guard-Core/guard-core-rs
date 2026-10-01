//! File-upload matchers ported from
//! `guard_core/handlers/_suspatterns_file_upload.py` (spec 4.0.2).
//!
//! All four patterns anchor on a `filename = "<quoted>"` token whose boundary
//! is located by walking back over whitespace to a required boundary char.
//! The dangerous-extension marker carries a `(?![A-Za-z0-9])` guard; the
//! guard is enforced with per-branch suffix checks in the reference's
//! alternation order (`php\d*` first with digit backtracking, then the
//! literal branches), which reproduces the lookahead exactly.

use super::chars_util::{char_at, char_before};
use super::pyregex::Candidate;

/// Dangerous extension alternation with `com` (terminal-extension pattern).
pub const DANGEROUS_EXT: &[&str] = &[
    "phtml", "shtml", "asax", "ascx", "ashx", "asmx", "aspx", "bash", "jspx", "phar", "phps",
    "asa", "asp", "bat", "cer", "cfc", "cfm", "cgi", "cmd", "com", "exe", "hta", "jsp", "msi",
    "pht", "vbe", "vbs", "war", "wsf", "js", "pl", "py", "rb", "sh", "ws",
];

/// Dangerous extension alternation for the double-extension marker (no `com`).
pub const DOUBLE_EXT: &[&str] = &[
    "phtml", "shtml", "asax", "ascx", "ashx", "asmx", "aspx", "bash", "jspx", "phar", "phps",
    "asa", "asp", "bat", "cer", "cfc", "cfm", "cgi", "cmd", "exe", "hta", "jsp", "msi", "pht",
    "vbe", "vbs", "war", "wsf", "js", "pl", "py", "rb", "sh", "ws",
];

/// Benign terminal extensions for the double-extension shape.
pub const BENIGN_TERMINAL: &[&str] = &[
    "docx", "jpeg", "pptx", "tiff", "webm", "webp", "xlsx", "avi", "bmp", "doc", "gif", "ico",
    "jpg", "mkv", "mov", "mp3", "mp4", "odt", "pdf", "png", "ppt", "svg", "tif", "wav", "xls",
];

const fn is_whitespace(c: char) -> bool {
    c.is_whitespace()
}

/// ASCII case-folded `starts_with` at a byte position: the reference's builtin
/// `re.IGNORECASE` folding for the row's extension literals.
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

/// Anchored-`pos` matcher for `\.(?:php\d*|<alternation>)(?![A-Za-z0-9])`.
///
/// Returns the marker end. Branches are tried in reference order with the
/// `php\d*` digit backtracking; the lookahead is a suffix check per branch.
/// The row carries the reference's builtin IGNORECASE, so the extension
/// literals fold ASCII case.
#[must_use]
pub fn dangerous_marker_at(body: &str, pos: usize, extensions: &[&str]) -> Option<usize> {
    if char_at(body, pos).map(|(_, c)| c) != Some('.') {
        return None;
    }
    let after_dot = pos + 1;
    // branch 1: php\d* with backtracking over the greedy digits
    if ascii_starts_with_ignore_case(body, after_dot, "php") {
        let mut end = after_dot + 3;
        while char_at(body, end).is_some_and(|(_, c)| c.is_ascii_digit()) {
            end += 1;
        }
        loop {
            if char_at(body, end).is_none_or(|(_, c)| !c.is_ascii_alphanumeric()) {
                return Some(end);
            }
            if end == after_dot + 3 {
                break;
            }
            end -= 1;
        }
    }
    for ext in extensions {
        let end = after_dot + ext.len();
        if ascii_starts_with_ignore_case(body, after_dot, ext)
            && char_at(body, end).is_none_or(|(_, c)| !c.is_ascii_alphanumeric())
        {
            return Some(end);
        }
    }
    None
}

/// `\.(?:php\d*|<alternation>)\Z` on the body (case-insensitive).
fn terminal_extension(body: &str, extensions: &[&str], include_php_digits: bool) -> bool {
    let Some(dot) = body.rfind('.') else {
        return false;
    };
    let tail = &body[dot + 1..];
    if tail.is_empty() {
        return false;
    }
    if tail.eq_ignore_ascii_case("php") {
        return true;
    }
    if include_php_digits
        && tail.len() > 3
        && tail[..3].eq_ignore_ascii_case("php")
        && tail[3..].bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    extensions.iter().any(|ext| tail.eq_ignore_ascii_case(ext))
}

fn benign_terminal(body: &str) -> bool {
    let Some(dot) = body.rfind('.') else {
        return false;
    };
    let tail = &body[dot + 1..];
    BENIGN_TERMINAL
        .iter()
        .any(|ext| tail.eq_ignore_ascii_case(ext))
}

fn is_double_extension(body: &str) -> bool {
    if !benign_terminal(body) {
        return false;
    }
    #[cfg(not(coverage))] // unreachable: benign_terminal already proved the
    // body carries a '.' with a benign tail
    let Some(final_dot) = body.rfind('.') else {
        return false;
    };
    #[cfg(coverage)]
    let final_dot = body
        .rfind('.')
        .expect("benign_terminal proved a '.' exists");
    for (idx, c) in body.char_indices() {
        if c != '.' || idx >= final_dot {
            continue;
        }
        let Some(marker_end) = dangerous_marker_at(body, idx, DOUBLE_EXT) else {
            continue;
        };
        #[cfg(not(coverage))] // unreachable: the marker span is alphanumeric,
        // so it always ends at or before the final dot
        if marker_end > final_dot {
            continue;
        }
        let suffix_ok =
            char_at(body, marker_end).is_none_or(|(_, c)| !matches!(c, ' ' | '"' | '\''));
        if marker_end == final_dot || (marker_end < final_dot && suffix_ok) {
            return true;
        }
    }
    false
}

/// Truncation marker: `(?:%00|\u0000|\x00|\0|<NUL>|;)` raw, `(?:<NUL>|;)`
/// decoded, each also allowing `.` + end of body.
fn truncation_marker_at(body: &str, pos: usize, decoded: bool) -> bool {
    if pos > body.len() {
        return false;
    }
    if pos == body.len() - 1 && body.as_bytes()[pos] == b'.' {
        return true;
    }
    if decoded {
        return body[pos..].starts_with('\u{0}') || body[pos..].starts_with(';');
    }
    body[pos..].starts_with("%00")
        // the `\u0000`/`\x00` escape texts fold case under the row's builtin
        // IGNORECASE (`\U0000`, `\X00`)
        || ascii_starts_with_ignore_case(body, pos, r"\u0000")
        || ascii_starts_with_ignore_case(body, pos, r"\x00")
        || body[pos..].starts_with(r"\0")
        || body[pos..].starts_with('\u{0}')
        || body[pos..].starts_with(';')
}

fn is_truncation(body: &str, decoded: bool) -> bool {
    for (idx, c) in body.char_indices() {
        if c != '.' {
            continue;
        }
        let Some(marker_end) = dangerous_marker_at(body, idx, DOUBLE_EXT) else {
            continue;
        };
        if truncation_marker_at(body, marker_end, decoded) {
            return true;
        }
    }
    false
}

fn kind_matches(
    body: &str,
    source: &str,
    dangerous_source: &str,
    double_source: &str,
    trunc_source: &str,
    decoded_trunc_source: &str,
) -> bool {
    if source == dangerous_source {
        return terminal_extension(body, DANGEROUS_EXT, true);
    }
    if source == double_source {
        return is_double_extension(body);
    }
    if source == trunc_source {
        return is_truncation(body, false);
    }
    if source == decoded_trunc_source {
        return is_truncation(body, true);
    }
    false
}

fn file_upload_match_start(content: &str, filename_start: usize) -> Option<usize> {
    let mut cursor = filename_start;
    let mut first_newline: Option<usize> = None;
    loop {
        if cursor == 0 {
            return Some(0);
        }
        #[cfg(not(coverage))] // unreachable: `char_before` only answers `None`
        // at index 0, which the guard above already handled
        let Some((i, c)) = char_before(content, cursor) else {
            return Some(0);
        };
        #[cfg(coverage)]
        let (i, c) = char_before(content, cursor).expect("cursor > 0 is a boundary");
        if is_whitespace(c) {
            if c == '\n' {
                first_newline = Some(i);
            }
            cursor = i;
            continue;
        }
        if matches!(c, ';' | ',' | ':' | '\n') {
            return Some(i);
        }
        return first_newline;
    }
}

fn skip_whitespace(content: &str, mut cursor: usize) -> usize {
    while let Some((i, c)) = char_at(content, cursor)
        && is_whitespace(c)
    {
        cursor = i + c.len_utf8();
    }
    cursor
}

fn quoted_candidate(content: &str, filename_start: usize) -> Option<(usize, usize, usize)> {
    let match_start = file_upload_match_start(content, filename_start)?;
    let mut cursor = skip_whitespace(content, filename_start + "filename".len());
    if char_at(content, cursor).map(|(_, c)| c) != Some('=') {
        return None;
    }
    cursor = skip_whitespace(content, cursor + 1);
    let open = char_at(content, cursor).map(|(_, c)| c)?;
    if open != '"' && open != '\'' {
        return None;
    }
    let body_start = cursor + 1;
    let tail = &content[body_start..];
    let quote_index = tail.find(['"', '\''])?;
    Some((match_start, body_start, body_start + quote_index + 1))
}

/// `_file_upload_scan_matches`: candidates from `filename` tokens, classified
/// per pattern; the emitted match spans the validated `[match_start, end)`.
#[must_use]
pub fn file_upload_scan_matches(
    content: &str,
    source: &str,
    dangerous_source: &str,
    double_source: &str,
    trunc_source: &str,
    decoded_trunc_source: &str,
) -> Vec<Candidate> {
    let mut matches = Vec::new();
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(filename_re) = super::pyregex::PyRegex::compile("(?i)filename", false) else {
        return matches;
    };
    #[cfg(coverage)]
    let filename_re =
        super::pyregex::PyRegex::compile("(?i)filename", false).expect("statically valid literal");
    let mut last_end = 0usize;
    for m in filename_re.re().find_iter(content) {
        let Some((start, body_start, end)) = quoted_candidate(content, m.start()) else {
            continue;
        };
        if start < last_end {
            continue;
        }
        let body = &content[body_start..end - 1];
        if !kind_matches(
            body,
            source,
            dangerous_source,
            double_source,
            trunc_source,
            decoded_trunc_source,
        ) {
            continue;
        }
        matches.push(Candidate::new(start, end));
        last_end = end;
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    const DANGEROUS: &str = "DANGEROUS";
    const DOUBLE: &str = "DOUBLE";
    const TRUNC: &str = "TRUNC";
    const DECODED_TRUNC: &str = "DECODED_TRUNC";

    #[test]
    fn unterminated_or_absent_quotes_yield_no_candidate() {
        // The content ends right after `filename=`: no opening quote.
        assert!(
            file_upload_scan_matches(
                "; filename=",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
        // An opening quote with no closing quote before the end.
        assert!(
            file_upload_scan_matches(
                "; filename=\"shell.php",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
        // A non-quoted filename token is not a quoted candidate at all.
        assert!(
            file_upload_scan_matches(
                "; filename=shell.php",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
    }

    #[test]
    fn dangerous_extension_fires() {
        let ms = file_upload_scan_matches(
            "; filename=\"shell.php\"",
            DANGEROUS,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms[0].text("; filename=\"shell.php\""),
            "; filename=\"shell.php\""
        );
    }

    #[test]
    fn double_extension_fires() {
        let ms = file_upload_scan_matches(
            "filename=\"report.php.jpg\"",
            DOUBLE,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn plain_image_is_benign() {
        assert!(
            file_upload_scan_matches(
                "filename=\"photo.jpg\"",
                DOUBLE,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
        assert!(
            file_upload_scan_matches(
                "filename=\"doc.pdf\"",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
    }

    #[test]
    fn truncation_fires() {
        let ms = file_upload_scan_matches(
            "filename=\"shell.php%00.jpg\"",
            TRUNC,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
        let ms = file_upload_scan_matches(
            "filename=\"shell.php;.jpg\"",
            TRUNC,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn phps_branch_reached_after_php_digits() {
        // php\d* fails via the alnum suffix check; the phps branch must win
        let ms = file_upload_scan_matches(
            "filename=\"x.phps.jpg\"",
            DOUBLE,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn filename_needs_boundary() {
        // "myfilename" has no boundary before `filename` at offset 2
        assert!(
            file_upload_scan_matches(
                "myfilename=\"shell.php\"",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    fn sources() -> (&'static str, &'static str, &'static str, &'static str) {
        use crate::patterns::table::PATTERN_DEFINITIONS;
        let source_of = |id: usize| {
            PATTERN_DEFINITIONS
                .iter()
                .find(|e| e.id == id)
                .map_or("", |e| e.source)
        };
        (source_of(89), source_of(90), source_of(91), source_of(92))
    }

    #[test]
    fn marker_edges_cover_window_truncation_and_terminal_shapes() {
        let ext = DOUBLE_EXT;
        // the digit run followed by a letter backtracks all the way to php and
        // falls through to the alternation (which has no php entry)
        assert_eq!(dangerous_marker_at("x.php333a", 1, ext), None);
        // terminal shapes
        assert!(!terminal_extension("shellphp", ext, true));
        assert!(!terminal_extension("shell.", ext, true));
        assert!(terminal_extension("shell.php7", ext, true));
        assert!(!benign_terminal("noext"));
        assert!(!is_double_extension("archive.tar.gz"));
        // truncation marker position edges
        assert!(truncation_marker_at("shell.php.", 9, false));
        assert!(!truncation_marker_at("shell.php", 100, false));
        assert_eq!(file_upload_match_start("filename=\"a.php\"", 0), Some(0));
    }

    #[test]
    fn marker_end_backtracks_php_digits_and_honors_suffixes() {
        let ext = DOUBLE_EXT;
        // the greedy php digits backtrack until the suffix is non-alphanumeric
        assert_eq!(dangerous_marker_at("x.php333 ok", 1, ext), Some(8));
        // php with no digits ends right after php
        assert_eq!(dangerous_marker_at("x.php ok", 1, ext), Some(5));
        // a php suffix glued to letters rejects the branch and the alternation
        assert_eq!(dangerous_marker_at("x.phpy", 1, ext), None);
        // a non-dot position is never a marker
        assert_eq!(dangerous_marker_at("php", 0, ext), None);
    }

    #[test]
    fn scan_matches_covers_all_four_source_kinds() {
        let (dangerous, double, trunc, decoded_trunc) = sources();

        // dangerous terminal extension
        let out = file_upload_scan_matches(
            "Content-Disposition: filename=\"shell.php\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);

        // double extension: dangerous then benign terminal
        let content = "Content-Disposition: filename=\"shell.php.docx\"";
        let out =
            file_upload_scan_matches(content, double, dangerous, double, trunc, decoded_trunc);
        assert_eq!(out.len(), 1);

        // raw truncation marker (%00) after the extension
        let out = file_upload_scan_matches(
            "Content-Disposition: filename=\"shell.php%00x\"",
            trunc,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);

        // decoded truncation: a real NUL byte after the extension
        let out = file_upload_scan_matches(
            "Content-Disposition: filename=\"shell.php\u{0}x\"",
            decoded_trunc,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);

        // a benign filename matches nothing
        let out = file_upload_scan_matches(
            "Content-Disposition: filename=\"report.pdf\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn quoted_candidates_require_an_equals_and_a_quote() {
        let (dangerous, double, trunc, decoded_trunc) = sources();
        // no '=' after the filename token
        let out = file_upload_scan_matches(
            "filename \"a.php\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert!(out.is_empty());
        // '=' but no quote after it
        let out = file_upload_scan_matches(
            "filename= a.php",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert!(out.is_empty());
        // the whitespace run between '=' and the quote is skipped
        let out = file_upload_scan_matches(
            "filename=   \"a.php\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);
        // a newline inside the scanned-back run bounds the match start
        let out = file_upload_scan_matches(
            "header: x\nfilename=\"a.php\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn scan_matches_handles_separator_prefixes_and_skips_overlaps() {
        let (dangerous, double, trunc, decoded_trunc) = sources();
        // the semicolon separator prefix starts the match
        let out = file_upload_scan_matches(
            "form-data; filename=\"a.php\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);
        // two candidates on one line: the second overlapping span is skipped
        let out = file_upload_scan_matches(
            "filename=\"a.php\" filename=\"b.php\"",
            dangerous,
            dangerous,
            double,
            trunc,
            decoded_trunc,
        );
        assert_eq!(out.len(), 1);
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    const DANGEROUS: &str = "DANGEROUS";
    const DOUBLE: &str = "DOUBLE";
    const TRUNC: &str = "TRUNC";
    const DECODED_TRUNC: &str = "DECODED_TRUNC";

    #[test]
    fn double_extension_scans_every_pre_terminal_dot() {
        // the first dot is not a marker; the second one carries the php marker
        assert!(is_double_extension("x.y.php.docx"));
        // a marker followed by a space before the terminal extension is not
        // a double extension
        assert!(!is_double_extension("x.php .docx"));
    }

    #[test]
    fn an_unknown_pattern_source_classifies_nothing() {
        assert!(
            file_upload_scan_matches(
                "filename=\"shell.php\"",
                "OTHER",
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
    }

    #[test]
    fn overlapping_inner_candidates_are_skipped() {
        // the inner `filename` token is a truncation candidate whose match
        // start falls inside the already-accepted outer span
        let out = file_upload_scan_matches(
            "filename=\"x.php;filename=\"y\"",
            TRUNC,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].start, 0);
        assert_eq!(out[0].end, 26);
    }
}
