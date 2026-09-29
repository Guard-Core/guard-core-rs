//! Request body value extraction: the engine-side port of the reference
//! body-scanning split, mirroring the Go engine's `bodyscan.go`.
//!
//! Sources: `guard_core/_utils/body_form_scan.py`, `body_json_scan.py`, and
//! `embedded_json_scan.py`.
//!
//! Instead of scanning the whole request body as one blob, the body is
//! extracted into the values the reference engine scans individually:
//!
//! ```text
//! form field name / value     request_body / request_body:form_field
//! multipart label / entry     request_body / request_body:multipart_field
//! JSON walk keys              request_body
//! JSON walk leaves            request_body (+ ":embedded_json" per embedded
//!                             walk level)
//! blob fallback               request_body (whole body)
//! ```
//!
//! The caller scans every extracted value through the normal
//! `guard_core_engine::detect::detect` path (first threat wins). A value with
//! `forced_category` set is a direct registry hit the reference reports from
//! the JSON walk without a pattern scan (`_mongo_operator_key_hit`): the
//! caller treats it as a threat of that category immediately.
//!
//! Deviations from the reference (mirroring the documented Go deviations, all
//! detection-neutral or noted):
//! - raw bytes become the engine-wide lossy `&str` representation at the
//!   adapter boundary: one U+FFFD per maximal invalid run instead of Python's
//!   one surrogateescape rune per byte. Ratios stay on the same side of the
//!   binary-like threshold for real payloads.
//! - JSON number leaves scan the literal JSON text instead of Python's float
//!   `repr`; JSON `NaN`/`Infinity` extensions are accepted like `json.loads`.
//! - excluded body fields (`excluded_detection_body_fields`) arrive as the
//!   [`ExcludedBodyFields`] set: an excluded form pair, multipart part, or
//!   JSON entry key is skipped outright, the reference's per-field routing.
//! - scan budgets (`detection_max_scan_values`/`_max_scan_chars`) are not
//!   modeled; the input is bounded by the adapter body cap instead.

use crate::detect::DetectConfig;
use crate::json_walk::{append_json_walk_entries, parse_ordered_json};
use crate::multipart_scan::{MultipartPart, parse_multipart_parts};

/// Context the reference scans form field values under.
pub const FORM_FIELD_CONTEXT: &str = "request_body:form_field";
/// Context the reference scans multipart part entries under.
pub const MULTIPART_FIELD_CONTEXT: &str = "request_body:multipart_field";
/// Context for the whole-body blob fallback and top-level JSON walks.
pub const REQUEST_BODY_CONTEXT: &str = "request_body";
/// Label for a multipart part without a `name` disposition parameter.
pub const MULTIPART_FILE_LABEL: &str = "file";
/// Direct JSON-walk registry hit category (`_mongo_operator_key_hit`).
pub const MONGO_OPERATOR_CATEGORY: &str = "nosql";

/// One value handed to the engine with the context label the reference scans
/// it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyScanValue {
    pub content: String,
    pub context: String,
    /// Set when the value is a direct registry hit (`_mongo_operator_key_hit`
    /// reports it unfiltered, without a pattern scan).
    pub forced_category: Option<&'static str>,
}

impl BodyScanValue {
    pub(crate) fn plain(text: impl Into<String>, ctx: &str) -> Self {
        Self {
            content: text.into(),
            context: ctx.to_owned(),
            forced_category: None,
        }
    }

    pub(crate) fn forced(content: impl Into<String>, category: &'static str) -> Self {
        Self {
            content: content.into(),
            context: REQUEST_BODY_CONTEXT.to_owned(),
            forced_category: Some(category),
        }
    }
}

/// The excluded detection body fields: the reference
/// `excluded_detection_body_fields` set (config or route resolution),
/// entries lowercased at resolution time.
///
/// Case-insensitive matching at the field-name boundary happens here
/// (`contains` lowercases its input), the reference's
/// `{k.lower() for k in ...}` coercion.
#[derive(Debug, Clone, Copy)]
pub struct ExcludedBodyFields<'a>(&'a std::collections::HashSet<String>);

impl Default for ExcludedBodyFields<'_> {
    fn default() -> Self {
        static EMPTY: std::sync::OnceLock<std::collections::HashSet<String>> =
            std::sync::OnceLock::new();
        Self(EMPTY.get_or_init(std::collections::HashSet::new))
    }
}

impl<'a> ExcludedBodyFields<'a> {
    /// Carry a resolved (lowercased) exclusion set.
    #[must_use]
    pub const fn new(set: &'a std::collections::HashSet<String>) -> Self {
        Self(set)
    }

    /// `true` when no fields are excluded.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    /// Case-insensitive membership: the field name lowercased before the
    /// lookup, like the reference's lowercase comparison.
    pub(crate) fn contains(self, name: &str) -> bool {
        self.0.contains(name.to_ascii_lowercase().as_str())
    }
}

/// `extractBodyScanValues`: the `_scan_request_body` routing on the lowered
/// content type - urlencoded form fields, multipart parts, JSON walks, and the
/// whole-body blob fallback.
///
/// Binary island reduction inside file parts uses
/// `config.binary_min_run_length`.
///
/// The no-exclusions form: identical to
/// [`extract_body_scan_values_with_exclusions`] with an empty set. The
/// adapters' existing extraction call sites keep compiling unchanged.
#[must_use]
pub fn extract_body_scan_values(
    raw_body: &str,
    content_type: &str,
    config: &DetectConfig,
) -> Vec<BodyScanValue> {
    extract_body_scan_values_with_exclusions(
        raw_body,
        content_type,
        config,
        ExcludedBodyFields::default(),
    )
}

/// [`extract_body_scan_values`] with the excluded detection body fields
/// carried through: an excluded form pair, multipart part, or JSON entry
/// key is skipped outright, the reference's per-field routing.
#[must_use]
pub fn extract_body_scan_values_with_exclusions(
    raw_body: &str,
    content_type: &str,
    config: &DetectConfig,
    excluded: ExcludedBodyFields<'_>,
) -> Vec<BodyScanValue> {
    let lowered = content_type.to_ascii_lowercase();
    if lowered.contains("application/x-www-form-urlencoded") {
        return append_form_body_values(Vec::new(), raw_body, excluded);
    }
    if lowered.contains("multipart/form-data") {
        return append_multipart_body_values(Vec::new(), raw_body, content_type, config, excluded);
    }
    if lowered.contains("json")
        && let Some(root) = parse_ordered_json(raw_body)
    {
        return append_json_walk_entries(Vec::new(), &root, REQUEST_BODY_CONTEXT, excluded);
    }
    vec![BodyScanValue::plain(raw_body, REQUEST_BODY_CONTEXT)]
}

/// `appendFormBodyValues`: `parse_qsl` pairs with `keep_blank_values`, the
/// name scanned as a `request_body` value, then the value as a `form_field`
/// value
/// (with the embedded JSON walk taking precedence over the raw string, exactly
/// like `_check_value_enhanced`'s embedded-JSON-first order).
fn append_form_body_values(
    mut values: Vec<BodyScanValue>,
    raw_body: &str,
    excluded: ExcludedBodyFields<'_>,
) -> Vec<BodyScanValue> {
    for pair in parse_form_pairs(raw_body) {
        // An excluded field name skips the whole pair (name and value).
        if excluded.contains(&pair.name) {
            continue;
        }
        values.push(BodyScanValue::plain(pair.name, REQUEST_BODY_CONTEXT));
        values = append_field_body_value(values, &pair.value, FORM_FIELD_CONTEXT, excluded);
    }
    values
}

/// `appendFieldBodyValue`: one form/multipart field value. A value that parses
/// as a JSON object or array is walked first (leaf context gains the
/// `:embedded_json` suffix) and the raw value is still scanned afterwards,
/// exactly like `_check_embedded_json_if_applicable` running the walk and then
/// `_check_value_enhanced` on the raw string: an attack can span the leaf
/// boundaries and exist only in the raw text (guard-core #122's
/// `body_raw_span_sqli_comment` vector).
fn append_field_body_value(
    mut values: Vec<BodyScanValue>,
    text: &str,
    ctx: &str,
    excluded: ExcludedBodyFields<'_>,
) -> Vec<BodyScanValue> {
    if let Some(root) = parse_ordered_json(text) {
        let walk_context = format!("{ctx}{}", crate::detect::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX);
        values = append_json_walk_entries(values, &root, &walk_context, excluded);
    }
    values.push(BodyScanValue::plain(text, ctx));
    values
}

/// `appendMultipartBodyValues`: when the body does not parse into at least one
/// leaf part, the whole raw body is scanned as one `request_body` blob value
/// (Python's `_scan_blob_body` fallback, including the no-parts-with-final-
/// boundary case the email parser reports as `is_multipart() == False`).
fn append_multipart_body_values(
    mut values: Vec<BodyScanValue>,
    raw_body: &str,
    content_type: &str,
    config: &DetectConfig,
    excluded: ExcludedBodyFields<'_>,
) -> Vec<BodyScanValue> {
    let (_, params) = parse_media_type_params(content_type);
    let boundary = param_lookup(&params, "boundary").unwrap_or_default();
    let parts = parse_multipart_parts(raw_body, boundary);
    if parts.is_empty() {
        values.push(BodyScanValue::plain(raw_body, REQUEST_BODY_CONTEXT));
        return values;
    }
    for part in parts {
        append_multipart_part_values(&mut values, &part, config, excluded);
    }
    values
}

/// `appendMultipartPartValues`: the per-part entry construction of
/// `_multipart_part_entries`, scanned with the label name scan in front,
/// exactly like the reference scanning the label once per entry (first-hit
/// identical). A part that yields no entries is not scanned at all, like the
/// reference.
///
/// The entries are the filename entry, every part header entry, and the
/// payload entries (islands when the part is a binary-like file part).
fn append_multipart_part_values(
    values: &mut Vec<BodyScanValue>,
    part: &MultipartPart<'_>,
    config: &DetectConfig,
    excluded: ExcludedBodyFields<'_>,
) {
    let (name, has_name) = part_disposition_param(part, "name");
    // An excluded part label skips the whole part (filename entry, part
    // headers, payload), exactly the reference's excluded-field routing.
    if has_name && excluded.contains(&name) {
        return;
    }
    let (plain_filename, plain_found) = part_disposition_param(part, "filename");
    let (filename, has_filename) = if plain_found {
        (plain_filename, true)
    } else {
        part_rfc2231_filename(part).map_or((String::new(), false), |f| (f, true))
    };
    let label: std::borrow::Cow<'_, str> = if has_name {
        std::borrow::Cow::Borrowed(name.as_str())
    } else {
        std::borrow::Cow::Borrowed(MULTIPART_FILE_LABEL)
    };

    let mut entries: Vec<String> = Vec::new();
    if has_filename {
        let sanitized = filename.replace(['"', '\''], "");
        entries.push(format!("filename=\"{sanitized}\""));
    }
    for header in &part.headers {
        entries.push(format!("{}: {}", header.name, header.value));
    }
    let payload = part.payload;
    if has_filename && crate::binary_islands::value_is_binary_like(payload) {
        entries.extend(
            crate::binary_islands::extract_binary_islands(payload, config.binary_min_run_length)
                .into_iter()
                .map(String::from),
        );
    } else if !payload.is_empty() {
        entries.push(payload.to_owned());
    }
    if entries.is_empty() {
        return;
    }
    values.push(BodyScanValue::plain(label.as_ref(), REQUEST_BODY_CONTEXT));
    for entry in &entries {
        *values = append_field_body_value(
            std::mem::take(values),
            entry,
            MULTIPART_FIELD_CONTEXT,
            excluded,
        );
    }
}

/// Extract a content-disposition parameter the way the Python email parser
/// does: tolerant semicolon splitting that respects quoted strings, outer
/// quotes stripped only when they pair, escaped quotes unescaped. Later
/// duplicates win (the Go port's map semantics).
fn part_disposition_param(part: &MultipartPart<'_>, param: &str) -> (String, bool) {
    first_header_value(part, "content-disposition").map_or_else(
        || (String::new(), false),
        |value| {
            let (_, params) = parse_header_params(&value);
            param_lookup(&params, param)
                .map_or_else(|| (String::new(), false), |found| (found.to_owned(), true))
        },
    )
}

/// `partRFC2231Filename` (`get_filename`'s RFC 2231 fallback): when no plain
/// filename parameter exists, the extended `filename*` piece, or the
/// `filename*0*`..`filename*N*` segments, are joined, the charset prefix
/// stripped, and the value percent-decoded.
fn part_rfc2231_filename(part: &MultipartPart<'_>) -> Option<String> {
    let value = first_header_value(part, "content-disposition")?;
    let (_, params) = parse_header_params(&value);
    if let Some(extended) = param_lookup(&params, "filename*") {
        return Some(decode_rfc2231_value(extended));
    }
    let mut pieces = String::new();
    let mut index = 0_usize;
    while let Some(piece) = param_lookup(&params, &format!("filename*{index}*")) {
        pieces.push_str(piece);
        index += 1;
    }
    if index == 0 {
        return None;
    }
    Some(decode_rfc2231_value(&pieces))
}

/// `decodeRFC2231Value`: strip the `charset'lang'` prefix, percent-decode
/// tolerantly.
fn decode_rfc2231_value(value: &str) -> String {
    // A charset/lang prefix is stripped only when both quotes are present;
    // otherwise the value stays untouched (the Go port's semantics).
    let rest = value.split_once('\'').map_or(value, |(_, after)| {
        after.split_once('\'').map_or(value, |(_, tail)| tail)
    });
    percent_decode_tolerant(rest)
}

fn first_header_value(part: &MultipartPart<'_>, lower_name: &str) -> Option<String> {
    part.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(lower_name))
        .map(|h| h.value.clone())
}

/// One `name=value` form pair, `unquote_plus`-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormPair {
    pub name: String,
    pub value: String,
}

/// `parseFormPairs` mirrors `urllib.parse.parse_qsl` with
/// `keep_blank_values=True` and the `"&"` separator.
///
/// Empty chunks are dropped, pairs partition on the first `"="`, missing
/// values are kept as empty strings, plus/space folding and tolerant
/// percent-decoding apply.
#[must_use]
pub fn parse_form_pairs(raw_body: &str) -> Vec<FormPair> {
    let mut pairs = Vec::new();
    for chunk in raw_body.split('&') {
        if chunk.is_empty() {
            continue;
        }
        let (name, value) = chunk
            .find('=')
            .map_or((chunk, ""), |idx| (&chunk[..idx], &chunk[idx + 1..]));
        pairs.push(FormPair {
            name: unquote_plus(name),
            value: unquote_plus(value),
        });
    }
    pairs
}

/// `unquote_plus` with `errors="surrogateescape"`.
///
/// `"+"` becomes a space and every valid `%XX` escape contributes its byte;
/// invalid escape sequences stay literal. Byte-oriented like the reference;
/// invalid UTF-8 sequences surface as U+FFFD at the decode boundary.
#[must_use]
pub fn unquote_plus(s: &str) -> String {
    if !s.contains('+') && !s.contains('%') {
        return s.to_owned();
    }
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h1), Some(h2)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push(h1 << 4 | h2);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `percentDecodeTolerant`: every valid `%XX` escape contributes its byte,
/// invalid sequences stay literal.
#[must_use]
pub fn percent_decode_tolerant(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h1), Some(h2)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(h1 << 4 | h2);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Ordered content-type / disposition parameters (names lowercased).
pub type HeaderParams = Vec<(String, String)>;

/// `parseMediaTypeParams`: split a Content-Type style header into its
/// lowercased main type and its parameters.
///
/// The main type keeps the part after `/` (the Go port lowercases the whole
/// first piece); splitting uses the same tolerant quoted-string handling as
/// the disposition parser.
#[must_use]
pub fn parse_media_type_params(value: &str) -> (String, HeaderParams) {
    let mut main_type = String::new();
    let mut params = HeaderParams::new();
    for (index, piece) in split_header_params(value).into_iter().enumerate() {
        if index == 0 {
            main_type = piece.trim().to_ascii_lowercase();
            continue;
        }
        if let Some((name, param)) = split_param_piece(&piece) {
            params.push((name, param));
        }
    }
    (main_type, params)
}

/// `parseHeaderParams`: a Content-Disposition style header value split into
/// its parameters (everything after the first `";"` piece) plus the main
/// value.
#[must_use]
pub fn parse_header_params(value: &str) -> (String, HeaderParams) {
    let pieces = split_header_params(value);
    let mut params = HeaderParams::new();
    for piece in pieces.iter().skip(1) {
        if let Some((name, param)) = split_param_piece(piece) {
            params.push((name, param));
        }
    }
    let main = pieces.first().map_or_else(String::new, String::clone);
    (main.trim().to_owned(), params)
}

/// Last-wins parameter lookup (the Go port's map semantics).
#[must_use]
pub fn param_lookup<'a>(params: &'a HeaderParams, name: &str) -> Option<&'a str> {
    params
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn split_param_piece(piece: &str) -> Option<(String, String)> {
    let idx = piece.find('=')?;
    let name = piece[..idx].trim().to_ascii_lowercase();
    let value = unquote_header_param(piece[idx + 1..].trim());
    Some((name, value))
}

/// `unquoteHeaderParam` mirrors the email parser's param unquoting: matching
/// outer quotes are stripped and escaped quotes and backslashes are
/// unescaped; asymmetric quotes are kept verbatim.
fn unquote_header_param(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return value.to_owned();
    }
    let inner = &value[1..value.len() - 1];
    let mut out = Vec::with_capacity(inner.len());
    let chars = inner.as_bytes();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == b'\\'
            && i + 1 < chars.len()
            && (chars[i + 1] == b'"' || chars[i + 1] == b'\\')
        {
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `splitHeaderParams`: split on semicolons that are not inside a quoted
/// string, mirroring `email.utils._parseparam`'s quote-aware splitting.
#[must_use]
pub fn split_header_params(value: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut start = 0_usize;
    let mut in_quotes = false;
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_quotes && c == b'\\' {
            i += 2;
            continue;
        }
        match c {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => {
                pieces.push(value[start..i].to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    pieces.push(value[start..].to_owned());
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::DetectConfig;

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

    fn extract(raw_body: &str, content_type: &str) -> Vec<(String, String)> {
        extract_body_scan_values_with_exclusions(
            raw_body,
            content_type,
            &corpus_config(),
            ExcludedBodyFields::default(),
        )
        .into_iter()
        .map(|v| (v.context, v.content))
        .collect()
    }

    #[test]
    fn parse_form_pairs_mirrors_parse_qsl() {
        let cases: &[(&str, Vec<(&str, &str)>)] = &[
            ("a=b&c", vec![("a", "b"), ("c", "")]),
            (
                "a=b=c&d=&=v&+x=%2F%zz&a=b",
                vec![
                    ("a", "b=c"),
                    ("d", ""),
                    ("", "v"),
                    (" x", "/%zz"),
                    ("a", "b"),
                ],
            ),
            ("a=1&&b=2&", vec![("a", "1"), ("b", "2")]),
            ("", vec![]),
        ];
        for (body, want) in cases {
            let got = parse_form_pairs(body);
            let got: Vec<(&str, &str)> = got
                .iter()
                .map(|p| (p.name.as_str(), p.value.as_str()))
                .collect();
            let want: Vec<(&str, &str)> = want.iter().map(|(a, b)| (*a, *b)).collect();
            assert_eq!(got, want, "parse_form_pairs({body:?})");
        }
    }

    #[test]
    fn form_body_extraction_contexts_and_order() {
        let values = extract(
            "system=<script>alert(1)</script>&note=hello",
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "system".to_owned()),
                (
                    FORM_FIELD_CONTEXT.to_owned(),
                    "<script>alert(1)</script>".to_owned()
                ),
                (REQUEST_BODY_CONTEXT.to_owned(), "note".to_owned()),
                (FORM_FIELD_CONTEXT.to_owned(), "hello".to_owned()),
            ]
        );
    }

    #[test]
    fn form_field_embedded_json_walk_contexts() {
        let values = extract(
            "data={\"a\":\"<script>alert(1)</script>\"}",
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "data".to_owned()),
                (REQUEST_BODY_CONTEXT.to_owned(), "a".to_owned()),
                (
                    "request_body:form_field:embedded_json".to_owned(),
                    "<script>alert(1)</script>".to_owned()
                ),
                // The raw value still scans after the clean walk (walk first,
                // then raw: an attack can span the leaf boundaries).
                (
                    "request_body:form_field".to_owned(),
                    "{\"a\":\"<script>alert(1)</script>\"}".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn multipart_text_part_entries() {
        let body =
            "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--B0--\r\n";
        let values = extract(body, "multipart/form-data; boundary=B0");
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "note".to_owned()),
                (
                    MULTIPART_FIELD_CONTEXT.to_owned(),
                    "Content-Disposition: form-data; name=\"note\"".to_owned()
                ),
                (MULTIPART_FIELD_CONTEXT.to_owned(), "hello".to_owned()),
            ]
        );
    }

    #[test]
    fn multipart_file_part_entries_include_filename_and_headers() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"report.pdf\"\r\n\r\nbinary-file-payload\r\n--B0--\r\n";
        let values = extract(body, "multipart/form-data; boundary=B0");
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "upload".to_owned()),
                (
                    MULTIPART_FIELD_CONTEXT.to_owned(),
                    "filename=\"report.pdf\"".to_owned()
                ),
                (
                    MULTIPART_FIELD_CONTEXT.to_owned(),
                    "Content-Disposition: form-data; name=\"upload\"; filename=\"report.pdf\""
                        .to_owned()
                ),
                (
                    MULTIPART_FIELD_CONTEXT.to_owned(),
                    "binary-file-payload".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn multipart_json_body_walk_leaf_contexts() {
        let values = extract(
            "{\"system\":\"1 OR 1=1\",\"meta\":{\"deep\":\"x\"}}",
            "application/json",
        );
        assert_eq!(
            values,
            vec![
                (REQUEST_BODY_CONTEXT.to_owned(), "system".to_owned()),
                (REQUEST_BODY_CONTEXT.to_owned(), "1 OR 1=1".to_owned()),
                (REQUEST_BODY_CONTEXT.to_owned(), "meta".to_owned()),
                (REQUEST_BODY_CONTEXT.to_owned(), "deep".to_owned()),
                (REQUEST_BODY_CONTEXT.to_owned(), "x".to_owned()),
            ]
        );
    }

    #[test]
    fn mongo_operator_key_forces_a_nosql_hit() {
        let values = extract_body_scan_values_with_exclusions(
            "{\"$where\": \"1 OR 1=1\"}",
            "application/json",
            &corpus_config(),
            ExcludedBodyFields::default(),
        );
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].content, "$where");
        assert_eq!(values[0].forced_category, Some(MONGO_OPERATOR_CATEGORY));
    }

    #[test]
    fn non_json_body_with_json_content_type_falls_back_to_blob() {
        let values = extract("1 OR 1=1", "application/json");
        assert_eq!(
            values,
            vec![(REQUEST_BODY_CONTEXT.to_owned(), "1 OR 1=1".to_owned())]
        );
    }

    #[test]
    fn unknown_content_type_falls_back_to_blob() {
        let values = extract("anything at all", "application/octet-stream");
        assert_eq!(
            values,
            vec![(
                REQUEST_BODY_CONTEXT.to_owned(),
                "anything at all".to_owned()
            )]
        );
    }

    #[test]
    fn empty_file_part_content_yields_no_scan_for_that_part() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"f\"; filename=\"empty.bin\"\r\n\r\n\r\n--B0--\r\n";
        let values = extract(body, "multipart/form-data; boundary=B0");
        // label scan, filename entry, disposition header; no payload entry.
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].1, "f");
        assert_eq!(values[1].1, "filename=\"empty.bin\"");
        assert!(!values.iter().any(|(_, content)| content == "\u{0}"));
    }

    #[test]
    fn part_without_content_disposition_still_yields_entries() {
        let body =
            "--B0\r\nContent-Type: text/plain\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n";
        let values = extract(body, "multipart/form-data; boundary=B0");
        assert_eq!(
            values,
            vec![
                (
                    REQUEST_BODY_CONTEXT.to_owned(),
                    MULTIPART_FILE_LABEL.to_owned()
                ),
                (
                    MULTIPART_FIELD_CONTEXT.to_owned(),
                    "Content-Type: text/plain".to_owned()
                ),
                (
                    MULTIPART_FIELD_CONTEXT.to_owned(),
                    "<script>alert(1)</script>".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn rfc2231_extended_filename_is_detected() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename*=UTF-8''shell.php%0A.jpg\r\n\r\nharmless\r\n--B0--\r\n";
        let values = extract(body, "multipart/form-data; boundary=B0");
        assert_eq!(values[1].1, "filename=\"shell.php\n.jpg\"");
    }

    #[test]
    fn escaped_quote_in_filename_is_unescaped_and_stripped() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell\\\".php%00.jpg\"\r\n\r\nharmless\r\n--B0--\r\n";
        let values = extract(body, "multipart/form-data; boundary=B0");
        assert_eq!(values[1].1, "filename=\"shell.php%00.jpg\"");
    }

    #[test]
    fn binary_like_file_part_reduces_to_islands() {
        let payload = "\u{FFFD}".repeat(8) + &"a".repeat(20) + &"\u{FFFD}".repeat(8);
        let body = format!(
            "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n\r\n{payload}\r\n--B0--\r\n"
        );
        let values = extract(&body, "multipart/form-data; boundary=B0");
        let last = values.last().expect("island entry");
        assert_eq!(last.0, MULTIPART_FIELD_CONTEXT);
        assert_eq!(last.1, "a".repeat(20));
    }

    #[test]
    fn mostly_text_file_part_keeps_full_payload_scan() {
        let payload = "one null\u{0}byte in text".to_owned();
        let body = format!(
            "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\n\r\n{payload}\r\n--B0--\r\n"
        );
        let values = extract(&body, "multipart/form-data; boundary=B0");
        assert_eq!(values.last().expect("payload").1, payload);
    }

    #[test]
    fn boundary_mismatch_falls_back_to_whole_body_blob() {
        let raw =
            "--B0\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\npayload\r\n--B0--\r\n";
        let values = extract(raw, "multipart/form-data; boundary=DOES-NOT-MATCH");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, REQUEST_BODY_CONTEXT);
        assert!(values[0].1.starts_with("--B0"));
    }

    #[test]
    fn header_param_splitting_respects_quotes() {
        let (main, params) = parse_header_params("form-data; name=\"a;b\"; filename=\"x'.y\"");
        assert_eq!(main, "form-data");
        assert_eq!(param_lookup(&params, "name"), Some("a;b"));
        assert_eq!(param_lookup(&params, "filename"), Some("x'.y"));
    }

    #[test]
    fn media_type_params_lowercases_main_type_and_names() {
        let (main, params) = parse_media_type_params("Multipart/Form-Data; Boundary=B0");
        assert_eq!(main, "multipart/form-data");
        assert_eq!(param_lookup(&params, "boundary"), Some("B0"));
    }

    #[test]
    fn unquote_header_param_keeps_asymmetric_quotes() {
        assert_eq!(unquote_header_param("\"a\""), "a");
        assert_eq!(unquote_header_param("\"a"), "\"a");
        assert_eq!(unquote_header_param("a"), "a");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::detect::DetectConfig;

    fn config() -> DetectConfig {
        DetectConfig {
            max_content_length: 10_000,
            max_full_scan_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            binary_min_run_length: 8,
        }
    }

    #[test]
    fn excluded_multipart_parts_and_rfc2231_filenames_scan() {
        let boundary = "XBOUND";
        let b = boundary;
        let body = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"safe\"\r\n\r\nok\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"secret\"; filename=\"a.php\"\r\n\r\n<?php\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"f2\"; filename*0*=utf-8''up%2E;\r\n\
             filename*1*=\"php\"\r\n\r\npayload\r\n--{b}--\r\n"
        );
        let content_type = format!("multipart/form-data; boundary={boundary}");

        // everything scanned without exclusions
        let all = extract_body_scan_values(&body, &content_type, &config());
        assert!(!all.is_empty());

        // the excluded part label drops its values entirely
        let mut excluded = std::collections::HashSet::new();
        excluded.insert("secret".to_owned());
        let filtered = extract_body_scan_values_with_exclusions(
            &body,
            &content_type,
            &config(),
            ExcludedBodyFields::new(&excluded),
        );
        assert!(filtered.len() < all.len());
    }

    #[test]
    fn empty_and_headerless_parts_are_dropped() {
        let boundary = "XBOUND";
        // a completely bare part: no disposition, no headers, empty payload
        let b = boundary;
        let body = format!("--{b}\r\n\r\n\r\n--{b}--\r\n");
        let values = extract_body_scan_values(
            &body,
            &format!("multipart/form-data; boundary={boundary}"),
            &config(),
        );
        // a part with no name, no filename, and no entries contributes
        // nothing (the bare `file` label never renders)
        assert!(
            values
                .iter()
                .all(|value| value.content != MULTIPART_FILE_LABEL),
            "unexpected bare file label: {values:?}"
        );

        // a named part with only headers keeps its entries (the header line
        // alone is a value)
        let b = boundary;
        let body = format!("--{b}\r\nContent-Type: text/plain\r\n\r\n\r\n--{b}--\r\n");
        let values = extract_body_scan_values(
            &body,
            &format!("multipart/form-data; boundary={boundary}"),
            &config(),
        );
        assert!(
            values
                .iter()
                .any(|value| value.content.contains("Content-Type")),
            "the header entry should survive: {values:?}"
        );
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn excluded_body_fields_reports_emptiness() {
        assert!(ExcludedBodyFields::default().is_empty());
        let excluded = std::iter::once("password".to_owned()).collect();
        assert!(!ExcludedBodyFields::new(&excluded).is_empty());
    }

    #[test]
    fn percent_decoding_without_escapes_is_the_identity() {
        assert_eq!(percent_decode_tolerant("plain value"), "plain value");
    }
}
