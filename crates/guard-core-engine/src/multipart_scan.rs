//! Line-based multipart scanner mirroring the extracted-value semantics of
//! Python's email feedparser for multipart/form-data bodies.
//!
//! Source: `guard_core/_utils/body_form_scan._multipart_text_parts`, a direct
//! port of the Go engine's `multipartscan.go`.
//!
//! - preamble lines before the opening boundary are discarded, epilogue after
//!   the final boundary is discarded;
//! - part headers keep their raw name case and wire order; a folded
//!   continuation line is appended to the previous value with its original
//!   line break preserved (compat32 keeps the raw fold);
//! - the first colonless line inside a part ends the header block and that
//!   line and everything after it up to the next boundary is the payload
//!   (`MissingHeaderBodySeparatorDefect`);
//! - the line terminator preceding a boundary line belongs to the delimiter,
//!   everything else (including bare newlines) stays in the payload;
//! - a part whose Content-Type is multipart with a boundary parameter is a
//!   container: its leaf parts are walked in place (`message.walk`), the
//!   container itself produces no entries; a container without a boundary is
//!   an ordinary leaf.
//!
//! No closing boundary is tolerated: the part parsed so far is kept, matching
//! the email parser's `CloseBoundaryNotFoundDefect` behavior. The scanner is
//! line-based over the already-capped body string and part payloads are
//! borrowed slices of it (the engine body is always valid UTF-8, decoded
//! lossily at the adapter boundary).

/// One raw part header, in wire order and raw name case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeHeaderEntry {
    pub name: String,
    pub value: String,
}

/// One leaf part: raw headers plus the payload bytes as a slice of the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartPart<'a> {
    pub headers: Vec<MimeHeaderEntry>,
    pub payload: &'a str,
}

/// Split a multipart body into its leaf parts (nested multipart containers
/// expanded in place).
///
/// An empty boundary yields no parts, which routes the caller to the
/// whole-body blob fallback like the Python `is_multipart() == False` path.
#[must_use]
pub fn parse_multipart_parts<'a>(body: &'a str, boundary: &str) -> Vec<MultipartPart<'a>> {
    if boundary.is_empty() {
        return Vec::new();
    }
    parse_multipart_level(body, boundary)
}

fn parse_multipart_level<'a>(body: &'a str, boundary: &str) -> Vec<MultipartPart<'a>> {
    let delim = format!("--{boundary}");
    let final_mark = format!("{delim}--");
    let mut pos = 0_usize;

    // Preamble: skip lines until the opening boundary (or the final boundary,
    // which means zero parts).
    while pos <= body.len() {
        let (line_start, line_end, next) = next_line(body, pos);
        let bare = trim_cr_and_padding(&body[line_start..line_end]);
        if bare == delim {
            pos = next;
            break;
        }
        if bare.starts_with(&final_mark) {
            return Vec::new();
        }
        pos = next;
    }

    let mut parts = Vec::new();
    while pos <= body.len() {
        let (headers, payload, next, closed, was_final) = read_part(body, pos, &delim, &final_mark);
        parts = append_multipart_leaf_or_container(parts, headers, payload);
        if !closed || was_final {
            // Missing closing boundary (payload ran to the end of the input,
            // CloseBoundaryNotFoundDefect) or the multipart body was closed:
            // any epilogue is discarded.
            return parts;
        }
        pos = next;
    }
    parts
}

/// Read one part (headers plus payload) starting at `pos`. Reports whether a
/// boundary line terminated the part (`closed`) and whether that boundary was
/// the final one; a missing closing boundary ends the multipart body with the
/// payload running to the end of the input.
type ReadPart<'a> = (Vec<MimeHeaderEntry>, &'a str, usize, bool, bool);

#[allow(clippy::too_many_lines)] // faithful line-by-line port of readPart
fn read_part<'a>(body: &'a str, mut pos: usize, delim: &str, final_mark: &str) -> ReadPart<'a> {
    let mut headers: Vec<MimeHeaderEntry> = Vec::new();
    let mut in_headers = true;
    let mut payload_start: Option<usize> = None;
    while pos <= body.len() {
        let (line_start, line_end, line_next) = next_line(body, pos);
        let raw = &body[line_start..line_end];
        let content = trim_cr_and_padding(raw);
        if in_headers {
            if content.is_empty() {
                // Blank line: headers end, payload starts after it.
                in_headers = false;
                payload_start = Some(line_next);
            } else if !headers.is_empty() && (content.starts_with(' ') || content.starts_with('\t'))
            {
                // Folded continuation: keep the raw break and the line.
                let br = if raw.ends_with('\r') { "\r\n" } else { "\n" };
                let prev = headers.last_mut().expect("non-empty above");
                prev.value.push_str(br);
                prev.value.push_str(content);
            } else if let Some(idx) = content.find(':') {
                headers.push(MimeHeaderEntry {
                    name: content[..idx].to_owned(),
                    value: content[idx + 1..]
                        .trim_start_matches([' ', '\t'])
                        .to_owned(),
                });
            } else {
                // Colonless line: the header block ends and the line itself
                // opens the payload (compat32 defect behavior).
                in_headers = false;
                payload_start = Some(line_start);
            }
            pos = line_next;
            continue;
        }
        if content == delim || content.starts_with(final_mark) {
            let payload = payload_slice(body, payload_start, line_start);
            return (
                headers,
                payload,
                line_next,
                true,
                content.starts_with(final_mark),
            );
        }
        pos = line_next;
    }
    // No closing boundary: the payload runs to the end of the body.
    let payload = payload_start.map_or(body, |start| &body[start..]);
    (headers, payload, body.len() + 1, false, false)
}

/// Extract the payload bytes between `payload_start` and the start of the
/// boundary line; the terminator immediately before the boundary line belongs
/// to the delimiter, not the payload.
fn payload_slice(body: &str, payload_start: Option<usize>, boundary_line_start: usize) -> &str {
    let start = payload_start.unwrap_or(boundary_line_start);
    if boundary_line_start <= start {
        return "";
    }
    let mut end = boundary_line_start;
    if end > start && body.as_bytes()[end - 1] == b'\n' {
        end -= 1;
        if end > start && body.as_bytes()[end - 1] == b'\r' {
            end -= 1;
        }
    }
    #[cfg(not(coverage))] // unreachable: the CRLF strip guards keep
    // `end >= start`, so the slice never inverts
    if end < start {
        return "";
    }
    &body[start..end]
}

/// Strip the trailing CR and transport padding (trailing spaces and tabs) the
/// boundary comparison ignores.
fn trim_cr_and_padding(line: &str) -> &str {
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.trim_end_matches([' ', '\t'])
}

/// Split the next line: `(line_start, line_end_excluding_newline, next_pos)`.
/// A final line without a terminator ends at the body end.
fn next_line(body: &str, pos: usize) -> (usize, usize, usize) {
    let line_start = pos;
    body.as_bytes()[pos..]
        .iter()
        .position(|b| *b == b'\n')
        .map_or((line_start, body.len(), body.len() + 1), |idx| {
            (line_start, pos + idx, pos + idx + 1)
        })
}

/// Either expand a nested multipart container (`message.walk` descends; the
/// container itself produces no entries) or append the part as a leaf.
fn append_multipart_leaf_or_container<'a>(
    mut parts: Vec<MultipartPart<'a>>,
    headers: Vec<MimeHeaderEntry>,
    payload: &'a str,
) -> Vec<MultipartPart<'a>> {
    let content_type = first_header_value_or_empty(&headers, "content-type");
    let (main_type, params) = crate::body_scan::parse_media_type_params(&content_type);
    // `get_content_maintype() == "multipart"`: the piece before the "/".
    let boundary = if main_type.split('/').next() == Some("multipart") {
        crate::body_scan::param_lookup(&params, "boundary").unwrap_or_default()
    } else {
        ""
    };
    if !boundary.is_empty() {
        parts.extend(parse_multipart_level(payload, boundary));
        return parts;
    }
    parts.push(MultipartPart { headers, payload });
    parts
}

fn first_header_value_or_empty(headers: &[MimeHeaderEntry], lower_name: &str) -> String {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(lower_name))
        .map_or_else(String::new, |h| h.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_two_text_parts() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--B0\r\nContent-Disposition: form-data; name=\"n2\"\r\n\r\nthere\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].payload, "hello");
        assert_eq!(parts[1].payload, "there");
        assert_eq!(
            parts[0].headers,
            vec![MimeHeaderEntry {
                name: "Content-Disposition".to_owned(),
                value: "form-data; name=\"note\"".to_owned()
            }]
        );
    }

    #[test]
    fn empty_boundary_yields_no_parts() {
        assert!(parse_multipart_parts("--B0\r\n\r\nx\r\n--B0--", "").is_empty());
    }

    #[test]
    fn preamble_and_epilogue_discarded() {
        let body = "preamble\r\n--B0\r\n\r\npayload\r\n--B0--\r\nepilogue\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "payload");
    }

    #[test]
    fn final_boundary_first_means_no_parts() {
        let body = "--B0--\r\nx\r\n";
        assert!(parse_multipart_parts(body, "B0").is_empty());
    }

    #[test]
    fn missing_closing_boundary_keeps_part() {
        let body =
            "--B0\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\npayload-without-close";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "payload-without-close");
    }

    #[test]
    fn colonless_line_opens_the_payload() {
        // compat32 defect behavior: the colonless line itself and everything
        // after it up to the next boundary is the payload.
        let body = "--B0\r\nnot-a-header\r\npayload line\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert!(parts[0].headers.is_empty());
        assert_eq!(parts[0].payload, "not-a-header\r\npayload line");
    }

    #[test]
    fn folded_header_keeps_raw_break() {
        let body = "--B0\r\nContent-Disposition: form-data;\r\n name=\"a\"\r\n\r\nx\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts[0].headers[0].value, "form-data;\r\n name=\"a\"");
    }

    #[test]
    fn bare_newlines_stay_in_payload() {
        let body = "--B0\r\n\r\nline1\nline2\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts[0].payload, "line1\nline2");
    }

    #[test]
    fn nested_multipart_container_expands_in_place() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"files\"\r\nContent-Type: multipart/mixed; boundary=INNER\r\n\r\n--INNER\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\nleaf-bytes\r\n--INNER--\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1, "the container itself produces no entry");
        assert_eq!(parts[0].payload, "leaf-bytes");
        assert_eq!(parts[0].headers[0].value, "attachment; filename=\"a.bin\"");
    }

    #[test]
    fn container_without_boundary_is_an_ordinary_leaf() {
        let body = "--B0\r\nContent-Type: multipart/mixed\r\n\r\nnot-really-nested\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "not-really-nested");
    }

    #[test]
    fn transport_padding_on_boundary_lines_is_ignored() {
        let body = "--B0  \r\n\r\npayload\r\n--B0--  \t\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "payload");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn a_missing_boundary_yields_no_parts() {
        let body = "Content-Disposition: form-data; name=\"f\"\r\n\r\nbody";
        let parts = parse_multipart_parts(body, "NO_SUCH_BOUNDARY");
        assert!(parts.is_empty());
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;

    #[test]
    fn a_payload_newline_at_the_boundary_strips_down_to_the_start() {
        // the terminator immediately before the boundary line is the
        // delimiter's: a lone `\n` strip lands exactly on the payload start
        assert_eq!(payload_slice("\nZ", Some(0), 1), "");
        // a CRLF terminator strips both bytes
        assert_eq!(payload_slice("x\r\nBOUND", Some(0), 3), "x");
        // a payload byte that is no terminator keeps the whole span up to
        // the boundary line
        assert_eq!(payload_slice("xZ", Some(0), 1), "x");
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn a_part_with_no_payload_lines_yields_an_empty_payload() {
        // the blank header terminator sits directly against the final boundary
        let body = "--B0\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "");
    }

    #[test]
    fn a_bare_newline_before_the_boundary_stays_in_the_payload() {
        // the payload's last line ends in a bare LF (no CR), so the delimiter
        // strips only the LF
        let body = "--B0\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nabc\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "abc");
    }

    #[test]
    fn a_lone_newline_payload_collapses_to_empty() {
        // a payload of exactly one LF whose preceding line ended in CRLF:
        // both decrement below the payload start
        let body = "--B0\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\n--B0--\r\n";
        let parts = parse_multipart_parts(body, "B0");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].payload, "");
    }
}
