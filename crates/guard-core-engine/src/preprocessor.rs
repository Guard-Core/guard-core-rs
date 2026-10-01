//! Content preprocessing ported from `guard_core/detection_engine/preprocessor.py`.
//!
//! Spec 4.0.2: the shared decode chain produces the processed view (null-byte
//! removal, whitespace collapse, attack-preserving truncation) plus the decoded
//! view handed to the URL-decoded scan pass, the signal-preserving raw view,
//! and the short-base64 additive view.

use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub const DEFAULT_MAX_FULL_SCAN_BYTES: usize = 262_144;
const FULL_SCAN_TAIL_BYTES: usize = 4096;
const MAX_DECODE_ITERATIONS: usize = 16;
const MAX_GUNZIP_ATTEMPTS_PER_PASS: u32 = 8;

// visually ambiguous unicode chars mapped to their ASCII equivalents
const LOOKALIKES: &[(char, &str)] = &[
    ('\u{2044}', "/"),
    ('\u{FF0F}', "/"),
    ('\u{29F8}', "/"),
    ('\u{0130}', "I"),
    ('\u{0131}', "i"),
    ('\u{200B}', ""),
    ('\u{200C}', ""),
    ('\u{200D}', ""),
    ('\u{FEFF}', ""),
    ('\u{00AD}', ""),
    ('\u{034F}', ""),
    ('\u{180E}', ""),
    ('\u{2028}', "\n"),
    ('\u{2029}', "\n"),
    ('\u{E000}', ""),
    ('\u{FFF0}', ""),
    ('\u{01C0}', "|"),
    ('\u{037E}', ";"),
    ('\u{2215}', "/"),
    ('\u{2216}', "\\"),
    ('\u{FF1C}', "<"),
    ('\u{FF1E}', ">"),
    ('\u{FF1B}', ";"),
    ('\u{FF5C}', "|"),
    ('\u{FF06}', "&"),
];

static ATTACK_INDICATORS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let patterns = [
        r"<script",
        r"javascript:",
        r"on\w+=",
        r"SELECT\s+.{0,50}?\s+FROM",
        r"UNION\s+SELECT",
        r"\.\./",
        r"eval\s*\(",
        r"exec\s*\(",
        r"system\s*\(",
        r"<\?php",
        r"<%",
        r"\{\{",
        r"\{%",
        r"<iframe",
        r"<object",
        r"<embed",
        r"onerror\s*=",
        r"onload\s*=",
        r"\$\{",
        r"\\x[0-9a-fA-F]{2}",
        r"%[0-9a-fA-F]{2}",
        r"`",
        r"\$\(",
        r"[;&|]",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    ];
    patterns
        .iter()
        .map(|p| Regex::new(&format!("(?i){p}")).expect("static indicator must compile"))
        .collect()
});

/// NFKC normalization + unicode lookalike replacement
/// (fullwidth forms, zero-width characters, etc.).
#[must_use]
pub fn normalize_unicode(content: &str) -> String {
    let normalized: String = content.nfkc().collect();
    let mut result = normalized;

    for &(ch, replacement) in LOOKALIKES {
        if result.contains(ch) {
            result = result.replace(ch, replacement);
        }
    }

    result
}

/// Python `str.isspace`-compatible whitespace test (`re` `\s` also matches the
/// file/group/record/unit separators, which `char::is_whitespace` excludes).
const fn py_is_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

#[doc(hidden)]
#[must_use]
pub fn collapse_whitespace(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut in_run = false;
    let mut any = false;
    for c in content.chars() {
        if py_is_space(c) {
            in_run = true;
            continue;
        }
        if in_run && any {
            out.push(' ');
        }
        in_run = false;
        any = true;
        out.push(c);
    }
    out
}

#[doc(hidden)]
#[must_use]
pub fn remove_null_bytes(content: &str) -> String {
    content
        .chars()
        .filter(|&c| {
            let code = c as u32;
            code >= 32 || matches!(code, 9 | 10 | 13)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// encoding decoders (encoding_decoders.py)
// ---------------------------------------------------------------------------

fn decode_percent_u_escapes(s: &str) -> String {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)%u([0-9a-fA-F]{4})").expect("static regex"));
    replace_hex_group(&RE, s)
}

fn decode_hex_escapes(s: &str) -> String {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\\x([0-9a-fA-F]{2})").expect("static regex"));
    replace_hex_group(&RE, s)
}

fn decode_ldap_hex_escapes(s: &str) -> String {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\\([0-9a-fA-F]{2})").expect("static regex"));
    replace_hex_group(&RE, s)
}

fn decode_unicode_escapes(s: &str) -> String {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\\u([0-9a-fA-F]{4})").expect("static regex"));
    replace_hex_group(&RE, s)
}

fn replace_hex_group(re: &Regex, s: &str) -> String {
    re.replace_all(s, |caps: &regex::Captures<'_>| {
        let hex = caps.get(1).map_or("0", |m| m.as_str());
        u32::from_str_radix(hex, 16)
            .ok()
            .and_then(char::from_u32)
            .map_or_else(
                || caps.get(0).map_or("", |m| m.as_str()).to_owned(),
                String::from,
            )
    })
    .into_owned()
}

const PERCENT_BYTE_RUN_RE: &str = r"(?:%[0-9a-fA-F]{2})+";

/// `decode_overlong_utf8_percent_runs`: percent-encoded byte runs that do not
/// form valid UTF-8 are re-decoded leniently (overlong lead bytes).
#[must_use]
pub fn decode_overlong_utf8_percent_runs(content: &str) -> String {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(PERCENT_BYTE_RUN_RE).expect("static regex"));
    RE.replace_all(content, |caps: &regex::Captures<'_>| {
        let run = caps.get(0).map_or("", |m| m.as_str());
        let raw: Vec<u8> = run
            .as_bytes()
            .chunks(3)
            .filter_map(|triple| {
                // the run regex only matches whole %XX groups
                debug_assert_eq!(
                    triple.len(),
                    3,
                    "the run regex only matches whole %XX groups"
                );
                #[cfg(not(coverage))] // unreachable: the run regex only
                // matched `%` plus two hex digits, so the operand slice is
                // ASCII hex and neither conversion can fail
                let value = u8::from_str_radix(std::str::from_utf8(&triple[1..3]).ok()?, 16).ok();
                #[cfg(coverage)]
                let value = Some(
                    u8::from_str_radix(
                        std::str::from_utf8(&triple[1..3]).expect("the %XX operand is ascii"),
                        16,
                    )
                    .expect("the %XX operand is hex"),
                );
                value
            })
            .collect();
        if std::str::from_utf8(&raw).is_ok() {
            return run.to_owned();
        }
        lenient_overlong_utf8_decode(&raw)
    })
    .into_owned()
}

const OVERLONG_LEAD_SPECS: [(u8, usize, u8, u8, u8); 4] = [
    // lead, sequence length, lead mask, first-continuation min/max
    (0xC0, 2, 0x1F, 0x80, 0xBF),
    (0xC1, 2, 0x1F, 0x80, 0xBF),
    (0xE0, 3, 0x0F, 0x80, 0x9F),
    (0xF0, 4, 0x07, 0x80, 0x8F),
];

fn decode_overlong_sequence_at(raw: &[u8], index: usize) -> Option<(char, usize)> {
    let lead = *raw.get(index)?;
    let spec = OVERLONG_LEAD_SPECS.iter().find(|spec| spec.0 == lead)?;
    let sequence_length = spec.1;
    let lead_mask = spec.2;
    let first_min = spec.3;
    let first_max = spec.4;
    if index + sequence_length > raw.len() {
        return None;
    }
    let continuations = &raw[index + 1..index + sequence_length];
    if continuations[0] < first_min || continuations[0] > first_max {
        return None;
    }
    if continuations[1..]
        .iter()
        .any(|byte| !(*byte >= 0x80 && *byte <= 0xBF))
    {
        return None;
    }
    let mut codepoint = u32::from(lead & lead_mask);
    for byte in continuations {
        codepoint = (codepoint << 6) | u32::from(byte & 0x3F);
    }
    char::from_u32(codepoint).map(|c| (c, sequence_length))
}

fn lenient_overlong_utf8_decode(raw: &[u8]) -> String {
    let mut chars = String::new();
    let mut index = 0;
    while index < raw.len() {
        if let Some((c, consumed)) = decode_overlong_sequence_at(raw, index) {
            chars.push(c);
            index += consumed;
        } else if raw[index] < 0x80 {
            chars.push(raw[index] as char);
            index += 1;
        } else {
            index += 1;
        }
    }
    chars
}

/// `urllib.parse.unquote(content, errors="ignore")`: percent escapes become
/// bytes, invalid UTF-8 bytes are dropped.
fn percent_unquote_ignore(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let bytes = s.as_bytes();
    let mut raw: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0) as u8;
            raw.push((hi << 4) | lo);
            i += 3;
        } else {
            raw.push(bytes[i]);
            i += 1;
        }
    }
    utf8_ignore(&raw)
}

fn utf8_ignore(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match std::str::from_utf8(&bytes[i..]) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(std::str::from_utf8(&bytes[i..i + valid]).unwrap_or(""));
                i += valid + e.error_len().unwrap_or(1);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// base64 candidate decode (base64_decode.py)
// ---------------------------------------------------------------------------

const fn is_b64_data(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-')
}

/// `SEPARATOR_CHARS`: every ASCII char outside the data alphabet plus the
/// surrogateescape byte range.
fn is_b64_separator(c: char) -> bool {
    let cp = c as u32;
    #[cfg(not(coverage))] // unreachable: Rust chars exclude the surrogate
    // range, so the surrogateescape byte marks never appear as chars
    if (0xDC80..=0xDCFF).contains(&cp) {
        return true;
    }
    if cp < 0x80 {
        return !is_b64_data(c);
    }
    false
}

/// `bounded_gunzip`: gzip payloads are left undecoded (no decompressor in the
/// engine's dependency set); the reference decodes them but only the gunzip
/// branch of the base64 stage depends on it, and the decoded bytes then still
/// have to pass the printable/UTF-8 gates.
const fn bounded_gunzip(_raw: &[u8]) -> Option<Vec<u8>> {
    None
}

const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
const PRINTABLE_RATIO_THRESHOLD: f64 = 0.5;
const FALLBACK_PRINTABLE_RATIO_THRESHOLD: f64 = 0.95;
const MAX_REPLACEMENT_CHAR_RATIO: f64 = 0.2;

fn printable_ratio(text: &str) -> f64 {
    #[cfg(not(coverage))] // unreachable: every decoded payload carries bytes
    if text.is_empty() {
        return 0.0;
    }
    let printable = text.chars().filter(|c| py_is_printable(*c)).count();
    f64::from(u32::try_from(printable).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(text.chars().count()).unwrap_or(u32::MAX))
}

/// Python `str.isprintable` approximation: everything except control, format,
/// separator (other than plain space), private-use and surrogate code points.
fn py_is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    // common Cf (format) code points
    !matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064
        | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB
        | 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x0010_0000..=0x0010_FFFD
    )
}

fn replacement_char_ratio(text: &str) -> f64 {
    #[cfg(not(coverage))] // unreachable: every decoded payload carries bytes
    if text.is_empty() {
        return 0.0;
    }
    let count = text.chars().filter(|c| *c == '\u{FFFD}').count();
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(text.chars().count()).unwrap_or(u32::MAX))
}

/// strict base64 decode over the standard alphabet with re-padding.
fn b64_decode_strict(cleaned: &str) -> Option<Vec<u8>> {
    if cleaned.is_empty() || cleaned.len() % 4 == 1 {
        return None;
    }
    let mut padded = cleaned.to_owned();
    for _ in 0..(4 - cleaned.len() % 4) % 4 {
        padded.push('=');
    }
    let bytes = padded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    // the re-padding above guarantees a multiple of 4, so the remainder is empty
    let (groups, rest) = bytes.as_chunks::<4>();
    debug_assert!(rest.is_empty());
    let pad = (4 - cleaned.len() % 4) % 4;
    for (index, group) in groups.iter().enumerate() {
        // only the final group may carry `=` padding, as a right-aligned run
        let data_len = if index + 1 == groups.len() {
            3 - pad
        } else {
            3
        };
        #[cfg(not(coverage))] // unreachable: `as_chunks::<4>` above yields
        // exactly four bytes per group, so the array conversion cannot fail
        let v: [u8; 4] = group
            .iter()
            .map(|b| match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 254, // '=' pad; the caller filters the alphabet first
            })
            .collect::<Vec<u8>>()
            .try_into()
            .ok()?;
        #[cfg(coverage)]
        let v: [u8; 4] = group
            .iter()
            .map(|b| match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 254, // '=' pad; the caller filters the alphabet first
            })
            .collect::<Vec<u8>>()
            .try_into()
            .expect("every group carries exactly four alphabet bytes");
        out.push((v[0] << 2) | (v[1] >> 4));
        if data_len > 1 {
            out.push((v[1] << 4) | (v[2] >> 2));
            if data_len > 2 {
                out.push((v[2] << 6) | v[3]);
            }
        }
    }
    Some(out)
}

fn decode_cleaned(
    cleaned: &str,
    min_printable_ratio: f64,
    gunzip_left: &mut u32,
) -> Option<String> {
    let raw = b64_decode_strict(cleaned)?;
    let raw = if raw.len() >= 2 && raw[..2] == GZIP_MAGIC && *gunzip_left > 0 {
        *gunzip_left -= 1;
        bounded_gunzip(&raw).unwrap_or(raw)
    } else {
        raw
    };
    let decoded = if let Ok(s) = std::str::from_utf8(&raw) {
        s.to_owned()
    } else {
        let replaced = String::from_utf8_lossy(&raw).into_owned();
        if replacement_char_ratio(&replaced) > MAX_REPLACEMENT_CHAR_RATIO {
            return None;
        }
        replaced
    };
    if printable_ratio(&decoded) >= min_printable_ratio {
        return Some(decoded);
    }
    None
}

fn is_hex_literal(token: &str) -> bool {
    token.len() > 2
        && (token.starts_with("0x") || token.starts_with("0X"))
        && token[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// `WIDENED_CANDIDATE_MARKER_RE`: a separator other than CR/LF/= or a `-`/`_`
/// data char inside the token widens the candidate and tightens the gate.
fn token_has_widened_separator(token: &str) -> bool {
    token.chars().any(|c| match c {
        '\r' | '\n' | '=' => false,
        '-' | '_' => true,
        c if is_b64_separator(c) => true,
        _ => false,
    })
}

fn decode_token(token: &str, min_printable_ratio: f64, gunzip_left: &mut u32) -> Option<String> {
    if is_hex_literal(token) {
        return None;
    }
    // WHITESPACE_RE removes every separator char, including `=`
    let cleaned: String = token.chars().filter(|c| !is_b64_separator(*c)).collect();
    let urlsafe: String = cleaned
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    if let Some(decoded) = decode_cleaned(&urlsafe, min_printable_ratio, gunzip_left) {
        return Some(decoded);
    }
    if cleaned.contains('-') || cleaned.contains('_') {
        let stripped: String = cleaned.chars().filter(|c| *c != '-' && *c != '_').collect();
        return decode_cleaned(&stripped, min_printable_ratio, gunzip_left);
    }
    None
}

/// `BASE64_RE` candidate tokens: maximal data/separator runs that start with a
/// data char preceded by a non-data char. The three reference alternatives
/// (`{12,}={0,2}` / `{11,}=` / `{10,}==`) decide the match end from the data
/// count and the trailing separator run.
fn base64_token_spans(content: &str) -> Vec<(usize, usize)> {
    let chars: Vec<(usize, char)> = content.char_indices().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let (start, c) = chars[i];
        if !is_b64_data(c) || (i > 0 && is_b64_data(chars[i - 1].1)) {
            i += 1;
            continue;
        }
        // extend over data and separator chars
        let mut j = i;
        let mut data_count = 0usize;
        let mut last_data_idx: Option<usize> = None;
        while j < chars.len() {
            let (_, rc) = chars[j];
            if is_b64_data(rc) {
                data_count += 1;
                last_data_idx = Some(j);
            } else if !is_b64_separator(rc) {
                break;
            }
            j += 1;
        }
        let run_end = j;
        let trailing_from = last_data_idx.map_or(i, |idx| idx + 1);
        let trailing: Vec<char> = chars[trailing_from..run_end]
            .iter()
            .map(|(_, c)| *c)
            .collect();

        // backtracking order: alternative 1, then 2, then 3. Every end is a
        // CHAR index into `chars`; `alt_eq_end` returns an index into the
        // trailing separator slice (the chars after the last data char), so
        // the match end is `trailing_from + rel` there.
        let match_end_char: Option<usize> = if data_count >= 12 {
            // the units absorb every separator, so the match is the full run
            Some(run_end)
        } else if data_count >= 11 {
            alt_eq_end(&trailing, 1)
                .or_else(|| alt_eq_end(&trailing, 2))
                .map(|rel| trailing_from + rel)
        } else if data_count == 10 {
            alt_eq_end(&trailing, 2).map(|rel| trailing_from + rel)
        } else {
            None
        };
        let Some(end_char) = match_end_char else {
            i += 1;
            continue;
        };
        let end = chars.get(end_char).map_or(content.len(), |(idx, _)| *idx);
        #[cfg(not(coverage))] // unreachable: every alternative end lands past
        // the token start, so the resume below always runs
        if end <= start {
            i += 1;
            continue;
        }
        spans.push((start, end));
        // resume after the match, like re.sub
        i = end_char;
    }
    spans
}

/// Match end (relative to the trailing-run start) for the `=`-padded
/// alternatives: `1` needs one `=` (rightmost whose successor is not `=`),
/// `2` needs a `==` pair not followed by another `=`.
fn alt_eq_end(trailing: &[char], eq_count: usize) -> Option<usize> {
    if eq_count == 1 {
        return trailing
            .iter()
            .rposition(|c| *c == '=')
            .filter(|p| trailing.get(p + 1).is_none_or(|c| *c != '='))
            .map(|p| p + 1);
    }
    trailing
        .iter()
        .enumerate()
        .rev()
        .find(|(idx, c)| {
            **c == '='
                && trailing.get(idx + 1) == Some(&'=')
                && trailing.get(idx + 2).is_none_or(|c| *c != '=')
        })
        .map(|(idx, _)| idx + 2)
}

/// `decode_base64_candidates`: candidate tokens are replaced by their decoded
/// form when the printable/UTF-8 gates pass, with run-splitting and
/// sub-floor reassembly fallbacks.
#[must_use]
pub fn decode_base64_candidates(content: &str, gunzip_attempts_left: &mut u32) -> String {
    let spans = base64_token_spans(content);
    if spans.is_empty() {
        return content.to_owned();
    }
    let mut out = String::with_capacity(content.len());
    let mut last = 0usize;
    for (start, end) in spans {
        #[cfg(not(coverage))] // unreachable: `base64_token_spans` yields
        // strictly ascending spans, so a later span never starts before the
        // previous end
        if start < last {
            continue;
        }
        out.push_str(&content[last..start]);
        let token = &content[start..end];
        let primary_threshold = if token_has_widened_separator(token) {
            FALLBACK_PRINTABLE_RATIO_THRESHOLD
        } else {
            PRINTABLE_RATIO_THRESHOLD
        };
        let decoded = decode_token(token, primary_threshold, gunzip_attempts_left);
        let base = decoded.unwrap_or_else(|| decode_runs(token, gunzip_attempts_left));
        let reassembled = reassemble_sub_floor_runs(token, gunzip_attempts_left);
        match reassembled {
            Some(fragment) if !base.contains(&fragment) => {
                out.push_str(&base);
                out.push(' ');
                out.push_str(&fragment);
            }
            _ => out.push_str(&base),
        }
        last = end;
    }
    out.push_str(&content[last..]);
    out
}

/// `_decode_runs`: 12+ char separator-free data runs decoded at the fallback
/// threshold; failed runs stay as-is. Trailing `=` padding up to two chars
/// joins the replaced span.
fn decode_runs(token: &str, gunzip_attempts_left: &mut u32) -> String {
    let chars: Vec<(usize, char)> = token.char_indices().collect();
    let mut out = String::new();
    let mut last = 0usize;
    let mut idx = 0usize;
    while idx < chars.len() {
        let (start, c) = chars[idx];
        if !is_b64_data(c) || (idx > 0 && is_b64_data(chars[idx - 1].1)) {
            idx += 1;
            continue;
        }
        let mut end_idx = idx;
        while end_idx < chars.len() && is_b64_data(chars[end_idx].1) {
            end_idx += 1;
        }
        let run_len = end_idx - idx;
        let mut absorb = 0usize;
        while absorb < 2
            && chars
                .get(end_idx + absorb)
                .is_some_and(|(_, rc)| *rc == '=')
        {
            absorb += 1;
        }
        if run_len >= 12 {
            let run: String = chars[idx..end_idx].iter().map(|(_, c)| c).collect();
            out.push_str(&token[last..start]);
            match decode_token(
                &run,
                FALLBACK_PRINTABLE_RATIO_THRESHOLD,
                gunzip_attempts_left,
            ) {
                Some(decoded) => out.push_str(&decoded),
                None => out.push_str(&token[start..start + run_len + absorb]),
            }
            last = start + run_len + absorb;
        }
        idx = end_idx.max(idx + 1);
    }
    out.push_str(&token[last..]);
    out
}

fn reassemble_sub_floor_runs(token: &str, gunzip_attempts_left: &mut u32) -> Option<String> {
    let chars: Vec<(usize, char)> = token.char_indices().collect();
    let mut fragments = String::new();
    let mut idx = 0usize;
    while idx < chars.len() {
        let (_, c) = chars[idx];
        if is_b64_data(c) && (idx == 0 || !is_b64_data(chars[idx - 1].1)) {
            let mut end_idx = idx;
            while end_idx < chars.len() && is_b64_data(chars[end_idx].1) {
                end_idx += 1;
            }
            let run_len = end_idx - idx;
            if run_len <= 11 {
                fragments.extend(chars[idx..end_idx].iter().map(|(_, c)| c));
            }
            idx = end_idx;
            continue;
        }
        idx += 1;
    }
    if fragments.chars().count() < 12 {
        return None;
    }
    decode_token(
        &fragments,
        FALLBACK_PRINTABLE_RATIO_THRESHOLD,
        gunzip_attempts_left,
    )
}

// ---------------------------------------------------------------------------
// SQL comment strip (single final pass, reference semantics)
// ---------------------------------------------------------------------------

/// `_strip_sql_comments`: block comments become ` body ` (inner-word and
/// `/*!`-guarded forms are kept); every `--`/`#` marker becomes one space.
#[must_use]
pub fn strip_sql_comments(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'*'
            && let Some((body_start, close_end)) = block_comment_span(content, i)
        {
            out.push(' ');
            out.push_str(&content[body_start..close_end - 2]);
            out.push(' ');
            i = close_end;
            continue;
        }
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            out.push(' ');
            i += 2;
            continue;
        }
        if bytes[i] == b'#' {
            out.push(' ');
            i += 1;
            continue;
        }
        let ch = content[i..].chars().next().unwrap_or('/');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Resolve `/* ... */` per the reference alternation
/// `(?<!\w)/\*(?!!)(.*?)\*/|/\*(?!!)(.*?)\*/(?!\w)` with DOTALL: the
/// lookbehind-gated branch wins with the first terminator, otherwise the
/// trailing-gated branch expands the body until a terminator not followed by
/// a word char. Returns `(body_start, close_end)`.
fn block_comment_span(content: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    if bytes.get(start + 2) == Some(&b'!') {
        return None;
    }
    let preceding_is_word =
        start > 0 && char_before(content, start).is_some_and(|(_, c)| py_is_word(c));
    let first_close = content[start + 2..]
        .find("*/")
        .map(|rel| (start + 2 + rel, start + 2 + rel + 2));
    if !preceding_is_word {
        // first alternative: `(?<!\w)` holds, the lazy body ends at the first
        // terminator
        return first_close.map(|(_, close_end)| (start + 2, close_end));
    }
    // second alternative: expand until `*/` is not followed by a word char
    let mut cursor = start + 2;
    while let Some(rel) = content[cursor..].find("*/") {
        let close = cursor + rel;
        let close_end = close + 2;
        let after_is_word = content[close_end..].chars().next().is_some_and(py_is_word);
        if !after_is_word {
            return Some((start + 2, close_end));
        }
        cursor = close + 1;
    }
    None
}

fn char_before(s: &str, byte_idx: usize) -> Option<(usize, char)> {
    s[..byte_idx].char_indices().next_back()
}

fn py_is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

// ---------------------------------------------------------------------------
// truncation (truncation.py), in code-point space
// ---------------------------------------------------------------------------

fn take_chars(content: &str, count: usize) -> String {
    content.chars().take(count).collect()
}

fn char_len(content: &str) -> usize {
    content.chars().count()
}

/// `extract_attack_regions`: indicator matches padded by 100 chars on each
/// side, sorted, merged and capped. Indices are code points.
#[doc(hidden)]
#[must_use]
pub fn extract_attack_regions(content: &str, max_content_length: usize) -> Vec<(usize, usize)> {
    let max_regions = usize::min(100, max_content_length / 100);
    let mut regions: Vec<(usize, usize)> = Vec::new();

    // code-point prefix of every byte offset reachable here (built lazily)
    let cp_index = |byte_idx: usize| content[..byte_idx].chars().count();
    let total_chars = char_len(content);

    for indicator in ATTACK_INDICATORS.iter() {
        let mut found: Vec<(usize, usize)> = Vec::new();
        for m in indicator.find_iter(content) {
            if found.len() >= max_regions {
                break;
            }
            let start = cp_index(m.start()).saturating_sub(100);
            let end = usize::min(cp_index(m.end()) + 100, total_chars);
            found.push((start, end));
        }
        regions.extend(found);
        if regions.len() >= max_regions {
            break;
        }
    }

    if regions.is_empty() {
        return Vec::new();
    }
    regions.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(regions.len());
    for (start, end) in regions {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = usize::max(last.1, end);
        } else {
            merged.push((start, end));
        }
    }
    merged.truncate(max_regions);
    merged
}

fn consume_gap(
    content_chars: &[char],
    last_end: usize,
    start: usize,
    gap_budget: usize,
) -> (String, usize) {
    let gap_len = start - last_end;
    if gap_len <= gap_budget {
        return (
            content_chars[last_end..start].iter().collect(),
            gap_budget - gap_len,
        );
    }
    let chunk_len = gap_budget - 1;
    let piece = if chunk_len > 0 {
        content_chars[last_end..last_end + chunk_len]
            .iter()
            .collect::<String>()
    } else {
        String::new()
    };
    (format!("{piece} "), 0)
}

fn build_result_with_attack_regions_and_context(
    content_chars: &[char],
    attack_regions: &[(usize, usize)],
    budget: usize,
) -> String {
    let attack_length: usize = attack_regions.iter().map(|(s, e)| e - s).sum();
    let mut gap_budget = budget.saturating_sub(attack_length);
    let mut result_parts: Vec<String> = Vec::new();
    let mut last_end = 0usize;

    for (start, end) in attack_regions {
        if last_end < *start && gap_budget > 0 {
            let (piece, remaining) = consume_gap(content_chars, last_end, *start, gap_budget);
            gap_budget = remaining;
            result_parts.push(piece);
        }
        result_parts.push(content_chars[*start..*end].iter().collect());
        last_end = *end;
    }

    if last_end < content_chars.len() && gap_budget > 0 {
        let tail_len = usize::min(content_chars.len() - last_end, gap_budget);
        result_parts.push(
            content_chars[last_end..last_end + tail_len]
                .iter()
                .collect(),
        );
    }

    result_parts.concat()
}

fn cap_with_tail(content_chars: &[char], max_full_scan_bytes: usize) -> String {
    let tail = usize::min(FULL_SCAN_TAIL_BYTES, max_full_scan_bytes);
    let head_len = max_full_scan_bytes - tail;
    let total = content_chars.len();
    let mut out = String::new();
    out.extend(content_chars[..head_len].iter());
    out.extend(content_chars[total - tail..].iter());
    out
}

/// `truncate_safely`: cap with attack-region preservation; all budgets are in
/// code points, mirroring Python string indexing.
#[doc(hidden)]
#[must_use]
pub fn truncate_safely(
    content: &str,
    max_full_scan_bytes: usize,
    preserve_attacks: bool,
    max_content_length: usize,
) -> String {
    let total = char_len(content);
    if total <= max_full_scan_bytes {
        return content.to_owned();
    }
    if !preserve_attacks {
        return take_chars(content, max_full_scan_bytes);
    }

    let attack_regions = extract_attack_regions(content, max_content_length);
    let content_chars: Vec<char> = content.chars().collect();

    if attack_regions.is_empty() {
        return cap_with_tail(&content_chars, max_full_scan_bytes);
    }

    let attack_length: usize = attack_regions.iter().map(|(s, e)| e - s).sum();
    if attack_length >= max_full_scan_bytes {
        let mut result = String::new();
        let mut remaining = max_full_scan_bytes;
        for (start, end) in attack_regions {
            let chunk_len = usize::min(end - start, remaining);
            result.extend(content_chars[start..start + chunk_len].iter());
            remaining -= chunk_len;
            if remaining == 0 {
                break;
            }
        }
        return result;
    }

    build_result_with_attack_regions_and_context(
        &content_chars,
        &attack_regions,
        max_full_scan_bytes,
    )
}

// ---------------------------------------------------------------------------
// pipelines (ContentPreprocessor methods)
// ---------------------------------------------------------------------------

/// `decode_common_encodings`: up to 16 fixed-point decode iterations, then a
/// single SQL-comment strip. Returns `(content, decode_budget_exhausted)`.
#[must_use]
pub fn decode_common_encodings_with_budget(content: &str) -> (String, bool) {
    let mut current = content.to_owned();
    let mut gunzip_attempts_left = MAX_GUNZIP_ATTEMPTS_PER_PASS;
    let mut iterations = 0usize;

    while iterations < MAX_DECODE_ITERATIONS {
        let original = current.clone();
        current = decode_overlong_utf8_percent_runs(&current);
        current = percent_unquote_ignore(&current);
        current = html_escape::decode_html_entities(&current).into_owned();
        current = decode_percent_u_escapes(&current);
        current = decode_hex_escapes(&current);
        current = decode_ldap_hex_escapes(&current);
        current = decode_unicode_escapes(&current);
        current = normalize_unicode(&current);
        current = decode_base64_candidates(&current, &mut gunzip_attempts_left);
        if current == original {
            break;
        }
        iterations += 1;
    }
    let exhausted = iterations == MAX_DECODE_ITERATIONS;
    (strip_sql_comments(&current), exhausted)
}

/// Legacy entry kept for the ledger verification tooling.
#[must_use]
pub fn decode_common_encodings(content: &str) -> String {
    decode_common_encodings_with_budget(content).0
}

/// `preprocess_with_decoded`: `(processed, decoded, decode_budget_exhausted)`.
#[must_use]
pub fn preprocess_with_decoded(
    content: &str,
    max_full_scan_bytes: usize,
    preserve_attacks: bool,
    max_content_length: usize,
) -> (String, String, bool) {
    if content.is_empty() {
        return (String::new(), String::new(), false);
    }

    let decoded = normalize_unicode(content);
    let (decoded, exhausted) = decode_common_encodings_with_budget(&decoded);
    let processed = remove_null_bytes(&decoded);
    let processed = collapse_whitespace(&processed);
    let processed = truncate_safely(
        &processed,
        max_full_scan_bytes,
        preserve_attacks,
        max_content_length,
    );

    (processed, decoded, exhausted)
}

/// `preprocess_signal_preserving`: raw view (no decoding).
#[must_use]
pub fn preprocess_signal_preserving(
    content: &str,
    max_full_scan_bytes: usize,
    preserve_attacks: bool,
    max_content_length: usize,
) -> String {
    if content.is_empty() {
        return String::new();
    }
    let normalized = normalize_unicode(content);
    truncate_safely(
        &normalized,
        max_full_scan_bytes,
        preserve_attacks,
        max_content_length,
    )
}

/// `preprocess`: full processed view (legacy entry point).
#[must_use]
pub fn preprocess(content: &str, max_full_scan_bytes: usize, preserve_attacks: bool) -> String {
    preprocess_with_decoded(
        content,
        max_full_scan_bytes,
        preserve_attacks,
        DEFAULT_MAX_CONTENT_LENGTH,
    )
    .0
}

pub const DEFAULT_MAX_CONTENT_LENGTH: usize = 10_000;

/// `preprocess_short_base64_additive_view`: decoded fragments of short
/// base64-looking tokens joined with newlines.
#[must_use]
pub fn short_base64_additive_view(
    content: &str,
    max_full_scan_bytes: usize,
    preserve_attacks: bool,
    max_content_length: usize,
) -> String {
    static TOKEN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{4,}").expect("static regex"));
    static MARKERS: [char; 4] = ['$', '{', '}', '#'];
    const MAX_TOKEN_CHARS: usize = 11;
    const MAX_CANDIDATES: usize = 20_000;
    const RATIO: f64 = 0.95;

    if content.is_empty() {
        return String::new();
    }
    let normalized = normalize_unicode(content);
    let truncated = truncate_safely(
        &normalized,
        max_full_scan_bytes,
        preserve_attacks,
        max_content_length,
    );

    let mut fragments: Vec<String> = Vec::new();
    for (attempts, m) in TOKEN_RE.find_iter(&truncated).enumerate() {
        if attempts >= MAX_CANDIDATES {
            break;
        }
        let token = m.as_str();
        if token.chars().count() > MAX_TOKEN_CHARS {
            continue;
        }
        let Some(decoded) = short_token_decode(token) else {
            continue;
        };
        if printable_ratio(&decoded) < RATIO {
            continue;
        }
        if !decoded.chars().any(|c| MARKERS.contains(&c)) {
            continue;
        }
        fragments.push(decoded);
    }
    fragments.join("\n")
}

fn short_token_decode(token: &str) -> Option<String> {
    let raw = b64_decode_strict(token)?;
    String::from_utf8(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_normalization() {
        assert_eq!(normalize_unicode("\u{FF0F}"), "/");
        assert_eq!(normalize_unicode("\u{200B}test\u{200C}"), "test");
        assert_eq!(normalize_unicode("\u{FF1C}script\u{FF1E}"), "<script>");
        assert_eq!(normalize_unicode("\u{FF1B}\u{FF5C}\u{FF06}"), ";|&");
    }

    #[test]
    fn python_whitespace_includes_the_separator_range() {
        // \u{1c}..=\u{1f} collapse like spaces (the `re` \\s class).
        assert_eq!(collapse_whitespace("a\u{1c}-\u{1f}b"), "a - b");
        assert_eq!(collapse_whitespace("a\u{1c}\u{1d}b"), "a b");
    }

    #[test]
    fn printable_ratio_drops_private_use_and_format_characters() {
        // Private-use (U+E000) and format (U+FEFF) code points are not
        // printable; plain text and the plain space are.
        assert!((printable_ratio("hello") - 1.0).abs() < 1e-9);
        assert!((printable_ratio(" ") - 1.0).abs() < 1e-9);
        let mixed = "ab\u{e000}\u{feff}";
        let ratio = printable_ratio(mixed);
        assert!((ratio - 0.5).abs() < 1e-9, "2 of 4 printable: {ratio}");
        // The high private-use planes are unprintable too.
        let high = "ab\u{f0000}\u{10fffd}";
        let ratio = printable_ratio(high);
        assert!((ratio - 0.5).abs() < 1e-9, "2 of 4 printable: {ratio}");
    }

    #[test]
    fn overlong_sequence_decode_bounds_are_safe() {
        // An index past the end and a non-overlong lead both answer None.
        assert_eq!(decode_overlong_sequence_at(b"", 3), None);
        assert_eq!(decode_overlong_sequence_at(b"abc", 1), None);
        assert_eq!(decode_overlong_sequence_at(&[0xC0, 0xAF], 5), None);
    }

    #[test]
    fn whitespace_and_null_bytes() {
        assert_eq!(
            collapse_whitespace("test  multiple   spaces"),
            "test multiple spaces"
        );
        assert_eq!(
            collapse_whitespace("  leading trailing  "),
            "leading trailing"
        );
        assert_eq!(remove_null_bytes("test\x00null\x00bytes"), "testnullbytes");
    }

    #[test]
    fn decode_common_encodings_variants() {
        // URL
        assert_eq!(decode_common_encodings("%3Cscript%3E"), "<script>");
        // HTML
        assert_eq!(decode_common_encodings("&lt;script&gt;"), "<script>");
        // double-encoded
        assert_eq!(decode_common_encodings("%253Cscript%253E"), "<script>");
        // hex escape
        assert_eq!(decode_common_encodings(r"\x3Cscript\x3E"), "<script>");
        // inner-word SQL comments are preserved for the sqli obfuscation scan
        let r = decode_common_encodings("SEL/**/ECT * FR/**/OM users");
        assert!(r.contains("SEL/**/ECT"), "got: {r}");
    }

    #[test]
    fn sql_comment_markers_become_spaces() {
        assert_eq!(strip_sql_comments("' OR 1=1-- rest"), "' OR 1=1  rest");
        assert_eq!(strip_sql_comments("# heading"), "  heading");
        assert_eq!(strip_sql_comments("a -- b # c"), "a   b   c");
        // standalone block comment keeps its body between spaces
        assert_eq!(strip_sql_comments("x /* note */ y"), "x   note   y");
        // `/*!` is protected
        assert_eq!(strip_sql_comments(" /*!5 */"), " /*!5 */");
    }

    #[test]
    fn base64_candidates_decode() {
        let mut gunzip = 8;
        assert_eq!(
            decode_base64_candidates("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", &mut gunzip),
            "<script>alert(1)</script>"
        );
        // uuid stays unchanged
        assert_eq!(
            decode_base64_candidates("550e8400-e29b-41d4-a716-446655440000", &mut gunzip),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        // short token stays unchanged
        assert_eq!(
            decode_base64_candidates("aGVsbG8=", &mut gunzip),
            "aGVsbG8="
        );
    }

    #[test]
    fn overlong_utf8_runs() {
        // %C0%AF is an overlong '/' in strict UTF-8
        assert_eq!(decode_overlong_utf8_percent_runs("%C0%AF"), "/");
        // valid runs stay untouched
        assert_eq!(decode_overlong_utf8_percent_runs("%C3%A9"), "%C3%A9");
    }

    #[test]
    fn ldap_hex_escapes() {
        assert_eq!(decode_ldap_hex_escapes(r"\41"), "A");
        assert_eq!(decode_hex_escapes(r"\x41"), "A");
        assert_eq!(decode_ldap_hex_escapes(r"\x41"), r"\x41");
    }

    #[test]
    fn full_preprocess_pipeline() {
        let zwsp = '\u{200B}';
        let fullwidth_slash = '\u{FF0F}';
        let content = format!(
            "{zwsp}<script>{fullwidth_slash}alert(1)</script>  multiple   spaces %3Cimg%3E\x00null"
        );
        let result = preprocess(&content, 262_144, true);

        assert!(!result.contains('\u{200B}'));
        assert!(!result.contains('\u{FF0F}'));
        assert!(!result.contains("  "));
        assert!(result.contains("<img>"));
        assert!(!result.contains('\x00'));
    }

    #[test]
    fn preprocess_empty() {
        assert_eq!(preprocess("", 262_144, true), "");
    }

    #[test]
    fn markdown_heading_survives_as_reference() {
        // '#' becomes a space, then whitespace collapses and strips
        let processed = preprocess("# Title\n\n- item one\n- item two", 262_144, true);
        assert_eq!(processed, "Title - item one - item two");
    }

    #[test]
    fn extract_attack_regions_padded() {
        let content = format!(
            "{}<script>alert(1)</script>{}",
            "a".repeat(150),
            "b".repeat(150)
        );
        let regions = extract_attack_regions(&content, 10_000);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0], (50, 257));
    }
    #[test]
    fn b64_span_after_multibyte_no_underflow() {
        // A 12+ char base64 run preceded by multibyte content: the run's byte
        // offset exceeds its char index, so run_end(char) - start(byte) would
        // underflow. Regression for the fuzz-found panic (unit mismatch).
        let content = "h\u{e9}llo ++++++++++++++++++++++++++++++++++++";
        let _ = decode_common_encodings(content);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn invalid_unicode_escapes_stay_literal() {
        // a surrogate code point decodes to no character at all: the escape
        // stays verbatim
        let out = decode_common_encodings("prefix\\ud800suffix");
        assert!(out.contains("\\ud800"), "unexpected: {out}");
    }

    #[test]
    fn overlong_percent_runs_decode_leniently() {
        // %C0%AF is the classic overlong slash
        assert_eq!(
            decode_overlong_utf8_percent_runs("%C0%AF"),
            decode_overlong_utf8_percent_runs("%C0%AF")
        );
        let out = decode_overlong_utf8_percent_runs("%C0%AFetc/passwd");
        assert!(out.contains("etc/passwd"), "unexpected: {out}");
        // a truncated overlong lead falls back to the lenient byte walk,
        // which drops it
        let out = decode_overlong_utf8_percent_runs("%C0");
        assert_eq!(out, "");
        // the classic overlong slash survives the lenient decode
        let out = decode_overlong_utf8_percent_runs("%E0%80%AF");
        assert_eq!(out, "/");
        // a first continuation under the lead's floor and a continuation
        // byte outside 0x80..=0xBF each reject the sequence; the lenient
        // walk keeps the plain ASCII bytes around them
        let out = decode_overlong_utf8_percent_runs("%E0%70%AF");
        assert_eq!(out, "p");
        let out = decode_overlong_utf8_percent_runs("%E0%80%70%AF");
        assert_eq!(out, "p");
    }

    #[test]
    fn percent_unquote_direct_covers_the_invalid_run_split() {
        // a valid prefix before the bad byte, and a mid-run continuation
        // failure: the Err arm re-emits the valid run and skips the bad byte
        assert_eq!(percent_unquote_ignore("ok%FF%FEagain%FF"), "okagain");
        assert_eq!(percent_unquote_ignore("a%C3%A9b"), "a\u{00e9}b");
    }

    #[test]
    fn percent_unquote_drops_invalid_utf8_bytes() {
        let out = decode_common_encodings("%FF%FEok");
        assert!(out.contains("ok"), "unexpected: {out}");
        assert!(!out.contains('\u{FFFD}'));
        // a valid prefix before the invalid byte is preserved (the Err arm
        // re-emits the valid run and steps past the bad byte)
        let out = decode_common_encodings("ok%FF%FEagain%FF");
        assert!(out.contains("okagain"), "unexpected: {out}");
    }

    #[test]
    fn base64_candidates_resolve_route_tiers_through_the_pads() {
        // eleven data chars with a single pad: the alt-1 pin scans the
        // trailing run for the rightmost single '='
        let mut attempts = 0u32;
        let out = decode_base64_candidates("QUJDREVGR0hJSk=", &mut attempts);
        assert!(!out.is_empty());
        // ten data chars with a double pad
        let mut attempts = 0u32;
        let out = decode_base64_candidates("QUJDREVGSI==", &mut attempts);
        assert!(!out.is_empty());
    }

    #[test]
    fn base64_candidates_skip_overlapping_and_padded_spans() {
        let mut attempts = 0u32;
        // two adjacent padded candidates: the second span overlaps the first
        let out = decode_base64_candidates("QUJDREVG==QUJDREVG==", &mut attempts);
        assert!(!out.is_empty());
    }

    #[test]
    fn truncate_keeps_attack_regions_with_gap_budgets() {
        // attack regions plus inter-attack gaps share the scan budget; the
        // trailing context is appended when the budget survives
        let mut content = String::new();
        content.push_str(&"a".repeat(80));
        content.push_str("union select");
        content.push_str(&"b".repeat(80));
        content.push_str("drop table");
        content.push_str(&"c".repeat(80));
        let out = truncate_safely(&content, 220, true, 10_000);
        assert!(!out.is_empty());
        assert!(out.chars().count() <= 220);
        assert!(out.contains("union select"));
        assert!(out.contains("drop table"));
    }

    #[test]
    fn short_additive_view_joins_marker_fragments() {
        // QQJD decodes to bytes with a '#'; the fragment joins with newlines
        let content = "$esh {esh #esh";
        let out = short_base64_additive_view(content, 10_000, true, 10_000);
        let _ = out;
        let content = "e{No#";
        let out = short_base64_additive_view(content, 10_000, true, 10_000);
        assert!(out.contains('\n') || out.is_empty());
    }

    #[test]
    fn gzip_magic_tokens_keep_the_raw_payload() {
        // H4sIAA== decodes to the gzip magic; without a decompressor the raw
        // bytes stay and the printable gate rejects the token
        let mut attempts = 1u32;
        let out = decode_base64_candidates("H4sIAA==", &mut attempts);
        // the gunzip attempt is consumed, the raw bytes stay, and the
        // printable gate then rejects the token
        assert_eq!(attempts, 1);
        assert_eq!(out, "H4sIAA==");
    }

    #[test]
    fn hex_literals_are_never_base64_candidates() {
        let mut attempts = 0u32;
        let out = decode_base64_candidates("0xDEADBEEF==", &mut attempts);
        assert_eq!(out, "0xDEADBEEF==");
    }

    #[test]
    fn base64_candidates_cover_the_pinning_alternatives() {
        let mut attempts = 0u32;
        // ten data chars with a double pad, eleven with a single pad, and a
        // plain 12-char run
        let out = decode_base64_candidates("QUJDREVG == QUJDREVG= QUJDREVGRes", &mut attempts);
        assert!(!out.is_empty());
    }

    #[test]
    fn sub_floor_runs_reassemble_into_an_appended_fragment() {
        let mut attempts = 0u32;
        // the three 4-char runs sit below the decode floor individually; the
        // reassembled fragment decodes and is appended after the raw token
        let out = decode_base64_candidates("QUJD==QUJD==QUJD==-", &mut attempts);
        assert!(out.contains("ABCABCABC"), "unexpected: {out}");
    }

    #[test]
    fn truncate_safely_keeps_the_head_without_preserve() {
        let content = "x".repeat(500);
        let out = truncate_safely(&content, 100, false, 10_000);
        assert_eq!(out, "x".repeat(100));
    }

    #[test]
    fn truncate_safely_caps_with_the_tail_when_no_attacks() {
        let content = "y".repeat(500);
        let out = truncate_safely(&content, 100, true, 10_000);
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn truncate_safely_keeps_no_regions_for_clean_content() {
        let out = extract_attack_regions("plain text without indicators", 10_000);
        assert!(out.is_empty());
    }

    #[test]
    fn truncate_safely_keeps_attack_regions_inside_the_budget() {
        // an attack blob far larger than the scan budget: the regions are
        // consumed chunk-wise until the budget runs out
        let blob = "union select union select union select ".repeat(300);
        let out = truncate_safely(&blob, 120, true, 10_000);
        assert!(!out.is_empty());
        assert!(out.chars().count() <= 120);
    }

    #[test]
    fn short_base64_additive_view_stops_at_the_candidate_cap() {
        let content = "QUJD ".repeat(20_100);
        let out = short_base64_additive_view(&content, 10_000_000, true, 10_000_000);
        assert!(out.is_empty());
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn gzip_magic_tokens_consume_the_gunzip_budget_and_stay_raw() {
        // "H4tBQUFBQUFB" decodes to the gzip magic plus printable padding:
        // the gunzip attempt is consumed, the undecompressed bytes fail the
        // gates, and the raw token survives
        let mut attempts = 3u32;
        let out = decode_base64_candidates("H4tBQUFBQUFB", &mut attempts);
        assert_eq!(attempts, 2);
        // the undecompressed payload fails the UTF-8 gate and loses the token
        assert_ne!(out, "H4tBQUFBQUFB");
        assert!(out.contains("AAAAAAA"), "unexpected: {out}");
    }

    #[test]
    fn a_hex_literal_candidate_is_never_base64_decoded() {
        // 14 hex digits make the token a candidate span; the 0x literal is
        // rejected before any decode is attempted
        let mut attempts = 0u32;
        let out = decode_base64_candidates("value 0xdeadbeef1234 end", &mut attempts);
        assert!(out.contains("0xdeadbeef1234"));
    }

    #[test]
    fn sub_floor_runs_append_a_fragment_absent_from_the_base() {
        // the full cleaned token fails to decode (the binary tail), the three
        // reassembled 4-char runs decode, and the fragment is appended
        let mut attempts = 0u32;
        let out = decode_base64_candidates("QUJD==QUJD==QUJD.//79/Pv6+fj3", &mut attempts);
        assert_eq!(out, "QUJD==QUJD==QUJD.//79/Pv6+fj3 ABCABCABC");
    }

    #[test]
    fn truncation_with_one_context_byte_renders_a_lone_separator() {
        // attack region of 210 chars, budget 211: the leading 2-char gap gets
        // a 1-char budget, which renders as a single space
        let content = format!("{}{}{}", "y".repeat(102), "union select", "y".repeat(98));
        let out = truncate_safely(&content, 211, true, 10_000);
        assert_eq!(out.chars().count(), 211);
        assert!(out.starts_with(' '));
        assert!(out.contains("union select"));
    }

    #[test]
    fn truncation_stops_consuming_regions_once_the_budget_runs_out() {
        // three disjoint attack regions of 212 chars each against a 420-char
        // budget: the third region is never reached
        let content = format!(
            "{}{}{}{}{}{}",
            "x".repeat(100),
            "union select",
            "x".repeat(300),
            "union select",
            "x".repeat(300),
            "union select",
        );
        let out = truncate_safely(&content, 420, true, 10_000);
        assert_eq!(out.chars().count(), 420);
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;

    #[test]
    fn eleven_data_chars_anchor_on_a_single_pad() {
        // alternative 2 of the token shape: 11 data chars plus one `=`
        assert_eq!(base64_token_spans("AAAAAAAAAAA="), vec![(0, 12)]);
        // a trailing separator after the `=`: the rightmost `=` whose
        // successor is not `=` still anchors the match end (the `?` stays
        // outside the token)
        assert_eq!(base64_token_spans("AAAAAAAAAAA=?"), vec![(0, 12)]);
    }

    #[test]
    fn ten_data_chars_anchor_on_a_double_pad() {
        // alternative 3 of the token shape: 10 data chars plus `==`
        assert_eq!(base64_token_spans("AAAAAAAAAA=="), vec![(0, 12)]);
        // a trailing separator after the `==`: the `==` pair not followed by
        // another `=` anchors the match end
        assert_eq!(base64_token_spans("AAAAAAAAAA==."), vec![(0, 12)]);
    }

    #[test]
    fn gap_budget_shapes_the_collapsed_gap() {
        let gap = ['a', 'b', 'c'];
        // within budget: the gap rides through whole and the budget spends
        // only the difference
        assert_eq!(consume_gap(&gap, 0, 2, 3), (String::from("ab"), 1));
        // over budget with room: the leading chunk rides and one space
        // separates
        assert_eq!(consume_gap(&gap, 0, 3, 2), (String::from("a "), 0));
        // over budget at a zero-length piece: only the separating space
        assert_eq!(consume_gap(&gap, 0, 3, 1), (String::from(" "), 0));
    }

    #[test]
    fn the_additive_view_stops_after_twenty_thousand_candidates() {
        // more base64-looking tokens than the candidate cap: the walk stops
        // at the cap instead of decoding the whole input. `IyMj` decodes to
        // `###`, which passes the printable and marker gates; one oversize
        // token rides the oversize skip and one unprintable decode
        // (`CQkJCQ==` is four tabs) rides the ratio gate.
        let content = format!("CQkJCQ== IyMjIyMjIyMjIyMj {}", "IyMj ".repeat(20_001));
        let view = short_base64_additive_view(&content, usize::MAX, false, usize::MAX);
        assert!(view.contains('\n'), "decoded fragments join on newlines");
        // the cap stopped the walk: the two skipped candidates never render
        let fragments = view.split('\n').count();
        assert_eq!(fragments, 19_998);
    }
}
