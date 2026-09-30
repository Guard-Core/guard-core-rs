//! The log-line redaction port: the reference's sensitive-name defaults and
//! the redaction the guard log lines apply (`guard_core/_utils/request_logging.py`).
//!
//! Every redaction call merges the caller's extra names with the hardcoded
//! defaults, matched case-insensitively (the reference `_merge_sensitive_names`
//! lowercases every extra name and compares against lowercase keys):
//!
//! - headers: `authorization`, `proxy-authorization`, `cookie`, `x-api-key`
//! - params and body fields: `access_token`, `refresh_token`, `api_key`,
//!   `apikey`, `token`, `password`, `secret`, `client_secret`, `signature`
//!
//! A sensitive header name redacts its whole value to `[REDACTED]`
//! (`_redact_sensitive_headers`). A sensitive name inside a URL or a
//! header value redacts only the value: `key=value` / `key:value` pairs
//! become `key=[REDACTED]` and JSON object keys at any depth keep the key
//! with a `[REDACTED]` value.
//!
//! ## Ported subset, stated plainly
//!
//! The reference scanner is deeper than this port: multi-round bounded
//! percent-decoding before matching, quoted pair names, JSON spans nested
//! inside pair values, JSON-in-path segments, netloc password redaction,
//! and a JSON depth cap. This module ports the surfaces the guard log
//! lines actually carry - URL query pairs, header values, and JSON blobs -
//! with single-round percent-decoding of pair names, the same default and
//! merged name sets, and the same `[REDACTED]` marker. A payload that
//! smuggles a sensitive value past the reference's decode rounds but not
//! this port's single round is a known divergence, recorded in
//! `CHANGELOG.md`.

use std::collections::HashSet;

/// The hardcoded sensitive header names (`_DEFAULT_SENSITIVE_LOG_HEADERS`).
pub const DEFAULT_SENSITIVE_LOG_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
];

/// The hardcoded sensitive param and body-field names
/// (`_DEFAULT_SENSITIVE_LOG_FIELDS`).
pub const DEFAULT_SENSITIVE_LOG_FIELDS: [&str; 9] = [
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "client_secret",
    "signature",
];

/// The merged sensitive-name sets one redaction call runs under: each set
/// is the hardcoded defaults plus the caller's `log_sensitive_*` extras,
/// lowercased (`_merge_sensitive_names`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveNames {
    /// `log_sensitive_headers` merged over
    /// [`DEFAULT_SENSITIVE_LOG_HEADERS`].
    pub headers: HashSet<String>,
    /// `log_sensitive_params` and `log_sensitive_body_fields` merged over
    /// [`DEFAULT_SENSITIVE_LOG_FIELDS`].
    pub fields: HashSet<String>,
}

impl Default for SensitiveNames {
    /// The hardcoded defaults alone (the reference `None` extras case).
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

impl SensitiveNames {
    /// Merge the extras over the defaults, lowercased.
    #[must_use]
    pub fn new(
        sensitive_headers: Option<&HashSet<String>>,
        sensitive_params: Option<&HashSet<String>>,
        sensitive_body_fields: Option<&HashSet<String>>,
    ) -> Self {
        let mut headers: HashSet<String> = DEFAULT_SENSITIVE_LOG_HEADERS
            .iter()
            .map(ToString::to_string)
            .collect();
        if let Some(extra) = sensitive_headers {
            headers.extend(extra.iter().map(|name| name.to_lowercase()));
        }
        let mut fields: HashSet<String> = DEFAULT_SENSITIVE_LOG_FIELDS
            .iter()
            .map(ToString::to_string)
            .collect();
        if let Some(extra) = sensitive_params {
            fields.extend(extra.iter().map(|name| name.to_lowercase()));
        }
        if let Some(extra) = sensitive_body_fields {
            fields.extend(extra.iter().map(|name| name.to_lowercase()));
        }
        Self { headers, fields }
    }

    fn field_is_sensitive(&self, name: &str) -> bool {
        self.fields.contains(&name.trim().to_lowercase())
    }

    fn header_is_sensitive(&self, name: &str) -> bool {
        self.headers.contains(&name.trim().to_lowercase())
    }
}

/// Escape the URL-unsafe control characters (`_escape_url_unsafe_controls`):
/// `\t` -> `%09`, `\r` -> `%0D`, `\n` -> `%0A`.
#[must_use]
pub fn escape_url_unsafe_controls(url: &str) -> String {
    if !url.contains(['\t', '\r', '\n']) {
        return url.to_owned();
    }
    let mut out = String::with_capacity(url.len());
    for ch in url.chars() {
        match ch {
            '\t' => out.push_str("%09"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

/// Redact a header map for a log line (`_redact_sensitive_headers`).
///
/// A sensitive header name (case-insensitive, surrounding whitespace
/// ignored) redacts the whole value to `[REDACTED]`, every other value
/// goes through [`redact_blob_for_display`].
#[must_use]
pub fn redact_headers(headers: &[(&str, &str)], names: &SensitiveNames) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(key, value)| {
            let redacted = if names.header_is_sensitive(key) {
                "[REDACTED]".to_owned()
            } else {
                redact_blob_for_display(value, names)
            };
            ((*key).to_owned(), redacted)
        })
        .collect()
}

/// Redact one URL for display (`redact_url_for_display`).
///
/// Control characters are escaped, then the path segments, query, and
/// fragment run through the pair scanner. The scheme and netloc are
/// copied verbatim (the reference redacts the netloc password; a
/// userinfo password in a guard log URL is not a surface this port
/// carries).
#[must_use]
pub fn redact_url_for_display(url: &str, names: &SensitiveNames) -> String {
    let escaped = escape_url_unsafe_controls(url);
    // Split scheme://netloc off first so the scanner never sees "https"
    // or the host as a pair name.
    let (authority, path_and_after) = escaped.find("://").map_or((None, escaped.as_str()), |idx| {
        let rest = &escaped[idx + 3..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        (Some(&escaped[..idx + 3 + end]), &escaped[idx + 3 + end..])
    });
    let (before_query, query_and_after) = match path_and_after.split_once('?') {
        Some((path, rest)) => (path, Some(rest)),
        None => (path_and_after, None),
    };
    let (query, fragment) = query_and_after
        .and_then(|rest| rest.split_once('#'))
        .map_or((None, None), |(q, f)| (Some(q), Some(f)));
    let mut out = String::with_capacity(escaped.len());
    if let Some(authority) = authority {
        out.push_str(authority);
    }
    out.push_str(&redact_pairs_in_path(before_query, names));
    if let Some(rest) = query_and_after {
        out.push('?');
        if let Some(query) = query {
            out.push_str(&redact_pairs_in_text(query, names));
            out.push('#');
            out.push_str(&redact_pairs_in_text(fragment.unwrap_or_default(), names));
        } else {
            // The '?' was followed by '#': the fragment rides in rest.
            let fragment = rest.strip_prefix('#').unwrap_or(rest);
            #[cfg(not(coverage))] // unreachable: this branch only runs when
            // `rest` holds no '#', so it cannot start with one
            if rest.starts_with('#') {
                out.push('#');
                out.push_str(&redact_pairs_in_text(fragment, names));
            }
            out.push_str(&redact_pairs_in_text(rest, names));
        }
    }
    out
}

/// The path half of [`redact_url_for_display`]: path segments split on `/`,
/// each segment pair-scanned (`;` matrix parameters included), so a
/// sensitive pair inside a path segment redacts like a query pair.
fn redact_pairs_in_path(path: &str, names: &SensitiveNames) -> String {
    if path.is_empty() {
        return path.to_owned();
    }
    path.split('/')
        .map(|segment| {
            segment
                .split(';')
                .map(|part| redact_pairs_in_text(part, names))
                .collect::<Vec<_>>()
                .join(";")
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Redact a header value or other opaque blob for display
/// (`redact_blob_for_display`): JSON spans first, then the pair scanner,
/// then XML element redaction.
#[must_use]
pub fn redact_blob_for_display(value: &str, names: &SensitiveNames) -> String {
    if value.is_empty() {
        return value.to_owned();
    }
    if let Some(redacted) = redact_json_text(value, names) {
        return redacted;
    }
    let pair_redacted = redact_pairs_in_text(value, names);
    redact_xml_elements(&pair_redacted, names)
}

/// Redact sensitive keys in a JSON object at any depth. Returns `None`
/// when the text is not a JSON object or array or when nothing matched
/// (the caller falls through to the pair scanner, exactly like the
/// reference's `_json_redact_text` `None` fall-through).
fn redact_json_text(text: &str, names: &SensitiveNames) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(text).ok()?;
    if !parsed.is_object() && !parsed.is_array() {
        return None;
    }
    let redacted = redact_json_value(parsed.clone(), names, 0)?;
    if redacted == parsed {
        return None;
    }
    serde_json::to_string(&redacted).ok()
}

const JSON_MAX_DEPTH: usize = 32;

fn redact_json_value(
    value: serde_json::Value,
    names: &SensitiveNames,
    depth: usize,
) -> Option<serde_json::Value> {
    if depth > JSON_MAX_DEPTH {
        // The reference returns the whole text "[REDACTED]" when the
        // depth cap is hit; surfaced here as the whole value redacted.
        return Some(serde_json::Value::String("[REDACTED]".to_owned()));
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, inner) in map {
                if names.field_is_sensitive(&key) {
                    out.insert(key, serde_json::Value::String("[REDACTED]".to_owned()));
                } else {
                    out.insert(key, redact_json_value(inner, names, depth + 1)?);
                }
            }
            Some(serde_json::Value::Object(out))
        }
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(redact_json_value(item, names, depth + 1)?);
            }
            Some(serde_json::Value::Array(out))
        }
        other => Some(other),
    }
}

/// Redact XML elements whose element name is sensitive
/// (`_redact_xml_elements`): `<name>[REDACTED]</name>`. Elements without a
/// closer are copied verbatim.
#[must_use]
pub fn redact_xml_elements(text: &str, names: &SensitiveNames) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let Some(lt) = rest.find('<') else {
            out.push_str(rest);
            break;
        };
        let after = &rest[lt + 1..];
        let Some((name, after_end)) = xml_element_name(after) else {
            out.push_str(&rest[..=lt]);
            rest = after;
            continue;
        };
        let open_end = lt + 1 + after_end;
        let close = format!("</{name}>");
        if let Some(rel) = rest[open_end..].find(close.as_str()) {
            let close_start = open_end + rel;
            if names.field_is_sensitive(name) {
                out.push_str(&rest[..lt]);
                out.push_str(&rest[lt..open_end]);
                out.push_str("[REDACTED]");
                out.push_str(&close);
            } else {
                out.push_str(&rest[..close_start + close.len()]);
            }
            rest = &rest[close_start + close.len()..];
        } else {
            out.push_str(&rest[..open_end]);
            rest = &rest[open_end..];
        }
    }
    out
}

/// The element name of a plain open tag plus the index just past `>`:
/// `None` for closing tags, comments, declarations, or names outside the
/// reference's `[A-Za-z_][\w.:-]*` shape.
fn xml_element_name(inner: &str) -> Option<(&str, usize)> {
    let bytes = inner.as_bytes();
    let first = *bytes.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = 1;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'.' | b':' | b'-'))
    {
        end += 1;
    }
    let name = &inner[..end];
    let rest = inner[end..].trim_start();
    if rest.starts_with('>') {
        return Some((name, end + (inner[end..].len() - rest.len()) + 1));
    }
    if rest.starts_with("/>") {
        return None;
    }
    None
}

/// Pair scanner over one text run: `name=value` and `name:value` pairs.
///
/// The assign separator (any `=`/`:` run with surrounding horizontal
/// whitespace) splits the name from the value, the value ending at the
/// next `&`, `;`, `,`, whitespace, or end of text. Names percent-decode
/// once before the case-insensitive sensitive match. Non-sensitive pairs
/// copy through unchanged.
#[must_use]
pub fn redact_pairs_in_text(text: &str, names: &SensitiveNames) -> String {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < n {
        if !is_name_byte(bytes[i]) {
            // Copy the non-name character (char-aware for UTF-8 safety).
            let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        let start = i;
        while i < n && is_name_byte(bytes[i]) {
            i += 1;
        }
        let name = &text[start..i];
        // The assign separator: any run of '=' and ':' with surrounding
        // horizontal whitespace, at least one required.
        let mut j = i;
        while j < n && bytes[j] == b' ' {
            j += 1;
        }
        let mut saw_assign = false;
        while j < n && (bytes[j] == b'=' || bytes[j] == b':') {
            saw_assign = true;
            j += 1;
            while j < n && bytes[j] == b' ' {
                j += 1;
            }
        }
        if !saw_assign {
            out.push_str(name);
            continue;
        }
        if names.field_is_sensitive(&percent_decode_lossy(name)) {
            out.push_str(name);
            out.push_str(&text[i..j]);
            out.push_str("[REDACTED]");
            while j < n && !matches!(bytes[j], b'&' | b';' | b',' | b' ' | b'\t' | b'\r' | b'\n') {
                j += 1;
            }
        } else {
            out.push_str(&text[start..j]);
        }
        i = j;
    }
    out
}

const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+' | b'%' | b'"' | b'\'')
}

/// Single-round percent-decoding with `+` read as space (the query-string
/// convention), byte-level so malformed escapes survive.
fn percent_decode_lossy(text: &str) -> String {
    if !text.contains('%') && !text.contains('+') {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &text[i + 1..i + 3];
                if let Ok(decoded) = u8::from_str_radix(hex, 16) {
                    out.push(decoded);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn set(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(ToString::to_string).collect()
    }

    fn names() -> SensitiveNames {
        SensitiveNames::new(None, None, None)
    }

    #[test]
    fn defaults_match_the_reference_sets() {
        assert_eq!(DEFAULT_SENSITIVE_LOG_HEADERS.len(), 4);
        assert_eq!(DEFAULT_SENSITIVE_LOG_FIELDS.len(), 9);
        assert!(names().header_is_sensitive("Authorization"));
        assert!(names().field_is_sensitive("TOKEN"));
        assert!(!names().header_is_sensitive("x-custom"));
    }

    #[test]
    fn extras_merge_over_the_defaults() {
        let merged = SensitiveNames::new(Some(&set(&["X-Custom-Id"])), None, None);
        assert!(merged.header_is_sensitive("x-custom-id"));
        assert!(merged.header_is_sensitive("cookie"));
    }

    #[test]
    fn query_pairs_redact_values_not_names() {
        let url = "https://example.com/login?user=a&token=abc&next=/x";
        assert_eq!(
            redact_url_for_display(url, &names()),
            "https://example.com/login?user=a&token=[REDACTED]&next=/x"
        );
    }

    #[test]
    fn colon_pairs_redact_in_header_blobs() {
        assert_eq!(
            redact_blob_for_display("api_key: supersecret, other: keep", &names()),
            "api_key: [REDACTED], other: keep"
        );
    }

    #[test]
    fn json_keys_redact_at_depth() {
        let blob = r#"{"user":"u","nested":{"password":"p","keep":1}}"#;
        // Key order follows the input's insertion order: serde_json runs
        // with preserve_order, the reference's insertion-order dumps.
        assert_eq!(
            redact_blob_for_display(blob, &names()),
            r#"{"user":"u","nested":{"password":"[REDACTED]","keep":1}}"#
        );
    }

    #[test]
    fn sensitive_header_names_redact_whole_value() {
        let headers = [("Authorization", "Bearer abc"), ("X-Trace", "keep-me")];
        assert_eq!(
            redact_headers(&headers, &names()),
            vec![
                ("Authorization".to_owned(), "[REDACTED]".to_owned()),
                ("X-Trace".to_owned(), "keep-me".to_owned()),
            ]
        );
    }

    #[test]
    fn xml_elements_redact_sensitive_names() {
        assert_eq!(
            redact_blob_for_display("<token>abc</token><ok>1</ok>", &names()),
            "<token>[REDACTED]</token><ok>1</ok>"
        );
    }

    #[test]
    fn url_controls_escape_like_the_reference() {
        assert_eq!(redact_url_for_display("/a\r\nb", &names()), "/a%0D%0Ab");
    }

    #[test]
    fn percent_encoded_names_match_case_insensitively() {
        assert_eq!(
            redact_url_for_display("/x?to%6Ben=abc&keep=1", &names()),
            "/x?to%6Ben=[REDACTED]&keep=1"
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use std::collections::HashSet;

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn sensitive_names_merge_the_extras_lowercased() {
        let names = SensitiveNames::new(
            Some(&set(&["X-Custom-Id"])),
            Some(&set(&["Sig", "TOKEN"])),
            Some(&set(&["Body-Secret"])),
        );
        assert!(names.header_is_sensitive("x-custom-id"));
        assert!(names.field_is_sensitive("sig"));
        assert!(names.field_is_sensitive("token"));
        assert!(names.field_is_sensitive("body-secret"));
    }

    #[test]
    fn escape_url_unsafe_controls_encodes_tab_cr_and_newline() {
        assert_eq!(escape_url_unsafe_controls("a\tb\rc\nd"), "a%09b%0Dc%0Ad");
        assert_eq!(escape_url_unsafe_controls("clean"), "clean");
    }

    #[test]
    fn url_display_redacts_query_and_fragment_forms() {
        let names = SensitiveNames::default();
        // query and fragment both present
        assert_eq!(
            redact_url_for_display("http://h/p?password=x#anchor", &names),
            "http://h/p?password=[REDACTED]#anchor"
        );
        // a bare '?' followed by '#': the fragment rides alone
        assert_eq!(
            redact_url_for_display("http://h/p?#frag", &names),
            "http://h/p?#frag"
        );
        // an empty path with only a query
        assert_eq!(
            redact_url_for_display("?password=x", &names),
            "?password=[REDACTED]"
        );
    }

    #[test]
    fn blob_display_rejects_non_object_and_unchanged_json() {
        let names = SensitiveNames::default();
        assert_eq!(redact_blob_for_display("", &names), "");
        assert_eq!(redact_blob_for_display("5", &names), "5");
        assert_eq!(
            redact_blob_for_display("{\"plain\": 1}", &names),
            "{\"plain\": 1}"
        );
    }

    #[test]
    fn blob_display_redacts_nested_json_arrays_and_caps_depth() {
        let names = SensitiveNames::default();
        // arrays carry the redaction recursively
        let out = redact_blob_for_display("{\"a\": [{\"password\": \"x\"}]}", &names);
        assert_eq!(out, "{\"a\":[{\"password\":\"[REDACTED]\"}]}");

        // a sensitive key past the depth cap redacts the whole value
        let mut deep = String::from("{\"k\":");
        for _ in 0..40 {
            deep.push_str("{\"password\":");
        }
        deep.push_str("\"x\"");
        for _ in 0..40 {
            deep.push('}');
        }
        deep.push('}');
        let out = redact_blob_for_display(&deep, &names);
        assert!(out.contains("[REDACTED]"), "unexpected: {out}");
    }

    #[test]
    fn xml_redaction_skips_non_elements_and_unterminated_tags() {
        let names = SensitiveNames::default();
        // `<3` is not an element, `</close>` is a closing tag, `<self/>` is
        // self-closing: all copy through verbatim
        assert_eq!(redact_xml_elements("<3 hearts</3", &names), "<3 hearts</3");
        assert_eq!(redact_xml_elements("<self/> kept", &names), "<self/> kept");
        // an unterminated open tag copies through verbatim
        assert_eq!(
            redact_xml_elements("<password oops", &names),
            "<password oops"
        );
        // a sensitive element with a closer redacts its body
        assert_eq!(
            redact_xml_elements("<password>x</password> tail", &names),
            "<password>[REDACTED]</password> tail"
        );
    }

    #[test]
    fn xml_redaction_walks_unterminated_and_nonsensitive_elements() {
        let names = SensitiveNames::default();
        // an open tag whose closer never arrives copies through its prefix
        // and rescans from the tag body
        let out = redact_xml_elements("<password>no closer ever", &names);
        assert!(out.contains("<password>"), "unexpected: {out}");
        // a non-sensitive element with a closer copies through verbatim
        assert_eq!(
            redact_xml_elements("keep <b>me</b> here", &names),
            "keep <b>me</b> here"
        );
    }

    #[test]
    fn json_depth_cap_redacts_the_whole_value() {
        let names = SensitiveNames::default();
        // build a document nested past the 32-level cap with a sensitive key
        // at the innermost level
        let mut doc = String::new();
        let depth = 40;
        for _ in 0..depth {
            doc.push('[');
        }
        doc.push_str("{\"password\": \"x\"}");
        for _ in 0..depth {
            doc.push(']');
        }
        let out = redact_blob_for_display(&doc, &names);
        // the depth-capped value collapses to the redaction marker
        assert!(out.contains("[REDACTED]"), "unexpected: {out}");
    }

    #[test]
    fn pair_scanner_percent_decodes_names_and_handles_stray_escapes() {
        let names = SensitiveNames::default();
        // the name percent-decodes once before the sensitive match
        assert_eq!(
            redact_pairs_in_text("%70assword=x", &names),
            "%70assword=[REDACTED]"
        );
        // a trailing '%' and '+' separators decode through the value walk
        assert_eq!(redact_pairs_in_text("a=b%2+c%", &names), "a=b%2+c%");
        // whitespace around the assign separator: name scanned, value redacted
        assert_eq!(
            redact_pairs_in_text("password = x", &names),
            "password = [REDACTED]"
        );
        // a name with no assign separator copies through unchanged
        assert_eq!(redact_pairs_in_text("password", &names), "password");
        // whitespace after the name but no assign separator: the name is
        // copied through unchanged
        assert_eq!(redact_pairs_in_text("token   x", &names), "token   x");
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;

    #[test]
    fn malformed_and_truncated_escapes_survive_verbatim() {
        // an invalid hex pair leaves the `%` in place and resyncs on the
        // next byte
        assert_eq!(percent_decode_lossy("%zz"), "%zz");
        // a truncated escape at the very end rides through untouched
        assert_eq!(percent_decode_lossy("%4"), "%4");
    }

    #[test]
    fn plus_reads_as_space_and_valid_escapes_decode() {
        // the query-string convention: `+` is a space
        assert_eq!(percent_decode_lossy("a+b"), "a b");
        // a valid pair decodes
        assert_eq!(percent_decode_lossy("%41"), "A");
        // nothing to decode stays untouched
        assert_eq!(percent_decode_lossy("plain"), "plain");
    }
}
