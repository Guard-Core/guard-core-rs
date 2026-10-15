//! The request size and content-type gate: `max_request_size` and
//! `allowed_content_types`.
//!
//! This is the Rust family's port of the reference engine's
//! `request_size_content` check
//! (`guard_core/core/checks/implementations/request_size_content.py`). One
//! call, [`decide`], carries a request's size and content-type header values
//! through the reference's two sub-checks in its order:
//!
//! ```text
//! no max_request_size:                          skip the size check
//! no content-length header:                     pass the size check
//! content-length <= max_request_size:           pass
//! content-length >  max_request_size:           413 "Request too large"
//! no allowed_content_types:                     skip the type check
//! media type (before ";") in the allowed list:  pass
//! anything else (a missing header included):    415 "Unsupported content type"
//! ```
//!
//! Both limits are route-scoped in the reference (`RouteConfig.max_request_size`,
//! `RouteConfig.allowed_content_types`); there is no global knob, so the
//! config value is `Option`-shaped on both fields and the all-`None` default
//! is inert: [`decide`] passes everything.
//!
//! ## Details that mirror the reference exactly
//!
//! - The size comparison is `int(content_length) <= max_request_size`: a
//!   request at exactly the limit passes, one byte over is blocked, and a
//!   missing or empty `content-length` header passes (`if not content_length`
//!   in the reference). A content-length that is not an integer raises
//!   `ValueError` in the reference, which the pipeline answers with the
//!   fail-secure `500 "Security check failed"`; [`decide`] mirrors that with
//!   an [`Err`] return and a negative content-length passes (`-1 <= limit`),
//!   like Python's signed `int()`.
//! - The media type is `content_type.split(";")[0]` with no trim: the exact
//!   prefix before the first `;` is compared case-sensitively against the
//!   configured list, so `application/json; charset=utf-8` matches
//!   `application/json` and `application/json ; charset=utf-8` does not
//!   (trailing space), exactly as in Python. A missing `content-type`
//!   header compares as the empty string and is blocked by any non-empty
//!   allowed list.
//! - The size check runs first and wins: a request over the size limit with
//!   a disallowed content type is answered `413`, never `415`.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::request_limits::{decide, ContentLimits};
//!
//! let limits = ContentLimits {
//!     max_request_size: Some(1024),
//!     allowed_content_types: Some(vec!["application/json".to_owned()]),
//! };
//!
//! // At the limit passes, one byte over blocks with the 413 shape.
//! assert!(decide(&limits, Some("1024"), Some("application/json"))
//!     .unwrap()
//!     .is_none());
//! let block = decide(&limits, Some("1025"), Some("application/json"))
//!     .unwrap()
//!     .expect("over the limit");
//! assert_eq!(block.status, 413);
//! assert_eq!(block.body, "Request too large");
//!
//! // The media type is the prefix before ";", matched exactly.
//! assert!(decide(&limits, Some("10"), Some("application/json; charset=utf-8"))
//!     .unwrap()
//!     .is_none());
//! let block = decide(&limits, Some("10"), Some("text/plain"))
//!     .unwrap()
//!     .expect("disallowed type");
//! assert_eq!(block.status, 415);
//! assert_eq!(block.body, "Unsupported content type");
//!
//! // The default is inert.
//! assert!(decide(&ContentLimits::default(), Some("999999999"), Some("text/plain"))
//!     .unwrap()
//!     .is_none());
//! ```

use std::fmt;

/// The route-level content limits (the reference `RouteConfig.max_request_size`
/// and `RouteConfig.allowed_content_types`).
///
/// The default is both fields unset: the gate is inert and every request
/// passes, the reference's no-decorator shape (`applies_to` registers the
/// check only when a route carries either limit).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentLimits {
    /// `max_request_size`: the largest accepted `content-length` in bytes.
    /// `None` (or the reference's `0`-falsy shape) skips the size check.
    pub max_request_size: Option<u64>,
    /// `allowed_content_types`: the exact media types accepted. `None` skips
    /// the type check; an empty list behaves like `None` (the reference only
    /// registers the check for a truthy list).
    pub allowed_content_types: Option<Vec<String>>,
}

impl ContentLimits {
    /// Whether the gate has anything to enforce (the reference
    /// `applies_to` predicate: `max_request_size is not None or
    /// bool(allowed_content_types)`).
    #[must_use]
    pub fn has_rules(&self) -> bool {
        self.max_request_size.is_some()
            || self
                .allowed_content_types
                .as_ref()
                .is_some_and(|types| !types.is_empty())
    }
}

/// Which sub-check blocked the request (the reference's
/// `violation_type` event fields, carried for observability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentViolation {
    /// The `content-length` crossed `max_request_size`
    /// (`violation_type="max_request_size"`).
    MaxRequestSize,
    /// The media type was not in `allowed_content_types`
    /// (`violation_type="content_type"`).
    ContentType,
}

/// The block answer of a failed size or type check: the status and default
/// message body the reference's `create_error_response` answers with, plus
/// the `log_activity` reason string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentBlock {
    /// Which sub-check blocked.
    pub violation: ContentViolation,
    /// `413` for the size block, `415` for the type block.
    pub status: u16,
    /// The reference default message body.
    pub body: &'static str,
    /// The reference `log_activity` reason (`"Request size {n} exceeds
    /// limit: {max}"` / `"Invalid content type: {type}"`).
    pub reason: String,
}

/// A `content-length` header value that is not an integer: the error
/// [`decide`] fails with.
///
/// This mirrors the reference's `int(content_length)` `ValueError`, which
/// the pipeline answers with the fail-secure `500 "Security check failed"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLengthError {
    /// The rejected header value.
    pub value: String,
}

impl fmt::Display for ContentLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid content_length value '{}': expected an integer",
            self.value
        )
    }
}

impl std::error::Error for ContentLengthError {}

/// The media type of a `content-type` header value: the exact prefix before
/// the first `;`, with no trim (the reference `split(";")[0]`). A missing
/// header reads as the empty string.
#[must_use]
pub fn media_type(content_type: &str) -> &str {
    match content_type.split_once(';') {
        Some((prefix, _)) => prefix,
        None => content_type,
    }
}

/// Carry one request's size and content-type header values through the
/// reference's two sub-checks.
///
/// `content_length` is the raw `content-length` header value (`None` when
/// the header is absent) and `content_type` the raw `content-type` header
/// value (`None` when absent, compared as the empty string). `Ok(None)` means
/// the request passes; `Ok(Some(block))` is the reference's block answer; the
/// [`Err`] shape mirrors the reference's non-integer `content-length`
/// exception (answer the fail-secure `500 "Security check failed"`).
pub fn decide(
    limits: &ContentLimits,
    content_length: Option<&str>,
    content_type: Option<&str>,
) -> Result<Option<ContentBlock>, ContentLengthError> {
    if let Some(response) = size_block(limits, content_length)? {
        return Ok(Some(response));
    }
    Ok(content_type_block(limits, content_type))
}

/// The size sub-check: `None` passes, `Err` mirrors the reference's
/// `int(content_length)` exception.
fn size_block(
    limits: &ContentLimits,
    content_length: Option<&str>,
) -> Result<Option<ContentBlock>, ContentLengthError> {
    let Some(max) = limits.max_request_size else {
        return Ok(None);
    };
    let Some(raw) = content_length.filter(|raw| !raw.is_empty()) else {
        // `if not content_length` in the reference: an absent or empty
        // header passes the size check.
        return Ok(None);
    };
    // Python's int() strips surrounding whitespace and accepts a leading
    // sign; a negative value is `<= limit` and passes, like Python.
    let trimmed = raw.trim();
    let parsed: i64 = trimmed.parse().map_err(|_| ContentLengthError {
        value: raw.to_owned(),
    })?;
    if parsed <= 0 || u64::try_from(parsed).is_ok_and(|size| size <= max) {
        return Ok(None);
    }
    Ok(Some(ContentBlock {
        violation: ContentViolation::MaxRequestSize,
        status: 413,
        body: "Request too large",
        reason: format!("Request size {raw} exceeds limit: {max}"),
    }))
}

/// The content-type sub-check: `None` passes.
fn content_type_block(limits: &ContentLimits, content_type: Option<&str>) -> Option<ContentBlock> {
    let allowed = limits
        .allowed_content_types
        .as_ref()
        .filter(|types| !types.is_empty())?;
    let value = content_type.unwrap_or("");
    let media = media_type(value);
    if allowed.iter().any(|entry| entry == media) {
        return None;
    }
    Some(ContentBlock {
        violation: ContentViolation::ContentType,
        status: 415,
        body: "Unsupported content type",
        reason: format!("Invalid content type: {media}"),
    })
}

/// The status of a request body that did not arrive within
/// `body_read_timeout` (`SecurityConfig::body_read_timeout`): the adapter
/// answers it instead of forwarding a body it could not read in full.
pub const BODY_READ_TIMEOUT_STATUS: u16 = 408;

/// The body of the request-body read timeout answer.
pub const BODY_READ_TIMEOUT_MESSAGE: &str = "Request body read timed out";

#[cfg(test)]
mod tests {
    use super::*;

    fn json_only(max: u64) -> ContentLimits {
        ContentLimits {
            max_request_size: Some(max),
            allowed_content_types: Some(vec!["application/json".to_owned()]),
        }
    }

    #[test]
    fn default_is_inert_and_has_no_rules() {
        let limits = ContentLimits::default();
        assert!(!limits.has_rules());
        assert!(
            decide(&limits, Some("999999999999"), Some("text/plain"))
                .unwrap()
                .is_none()
        );
        assert!(decide(&limits, None, None).unwrap().is_none());
    }

    #[test]
    fn has_rules_tracks_each_field() {
        assert!(!ContentLimits::default().has_rules());
        assert!(
            ContentLimits {
                max_request_size: Some(1),
                ..ContentLimits::default()
            }
            .has_rules()
        );
        assert!(
            ContentLimits {
                allowed_content_types: Some(vec!["application/json".to_owned()]),
                ..ContentLimits::default()
            }
            .has_rules()
        );
        // An empty allowed list is the reference's falsy list: no rules.
        assert!(
            !ContentLimits {
                max_request_size: None,
                allowed_content_types: Some(Vec::new()),
            }
            .has_rules()
        );
        assert!(
            decide(
                &ContentLimits {
                    max_request_size: None,
                    allowed_content_types: Some(Vec::new()),
                },
                Some("999999999"),
                Some("text/plain")
            )
            .unwrap()
            .is_none(),
            "an empty allowed list never blocks"
        );
    }

    #[test]
    fn size_boundary_is_at_the_limit() {
        let limits = ContentLimits {
            max_request_size: Some(1024),
            ..ContentLimits::default()
        };
        assert!(decide(&limits, Some("1024"), None).unwrap().is_none());
        let block = decide(&limits, Some("1025"), None).unwrap().expect("over");
        assert_eq!(block.violation, ContentViolation::MaxRequestSize);
        assert_eq!(block.status, 413);
        assert_eq!(block.body, "Request too large");
        assert_eq!(block.reason, "Request size 1025 exceeds limit: 1024");
    }

    #[test]
    fn missing_or_empty_content_length_passes_the_size_check() {
        let limits = ContentLimits {
            max_request_size: Some(10),
            ..ContentLimits::default()
        };
        assert!(decide(&limits, None, None).unwrap().is_none());
        assert!(decide(&limits, Some(""), None).unwrap().is_none());
    }

    #[test]
    fn signed_and_padded_content_lengths_mirror_python_int() {
        let limits = ContentLimits {
            max_request_size: Some(10),
            ..ContentLimits::default()
        };
        // Surrounding whitespace is stripped before the parse.
        assert!(decide(&limits, Some(" 10 "), None).unwrap().is_none());
        // A leading sign parses; negative values pass like Python's `-1 <= 10`.
        assert!(decide(&limits, Some("-1"), None).unwrap().is_none());
        assert!(decide(&limits, Some("+5"), None).unwrap().is_none());
        let block = decide(&limits, Some(" 11 "), None).unwrap().expect("over");
        assert_eq!(block.reason, "Request size  11  exceeds limit: 10");
    }

    #[test]
    fn junk_content_length_is_an_error_not_a_block() {
        let limits = ContentLimits {
            max_request_size: Some(10),
            ..ContentLimits::default()
        };
        let error = decide(&limits, Some("about-twenty"), None).unwrap_err();
        assert_eq!(error.value, "about-twenty");
        assert_eq!(
            error.to_string(),
            "invalid content_length value 'about-twenty': expected an integer"
        );
        // Without a size limit the junk header is never read.
        assert!(
            decide(&ContentLimits::default(), Some("junk"), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn content_type_matches_the_exact_media_type_prefix() {
        let limits = ContentLimits {
            max_request_size: None,
            allowed_content_types: Some(vec![
                "application/json".to_owned(),
                "application/merge-patch+json".to_owned(),
            ]),
        };
        // Parameters are cut away, not stripped.
        assert!(
            decide(&limits, None, Some("application/json; charset=utf-8"))
                .unwrap()
                .is_none()
        );
        assert!(
            decide(&limits, None, Some("application/merge-patch+json"))
                .unwrap()
                .is_none(),
            "a type that merely contains an allowed entry as a substring must not pass"
        );
        // No trim: a space before the parameters stays part of the media type.
        let block = decide(&limits, None, Some("application/json ; charset=utf-8"))
            .unwrap()
            .expect("padded separator");
        assert_eq!(block.reason, "Invalid content type: application/json ");
        assert_eq!(block.status, 415);
        assert_eq!(block.body, "Unsupported content type");
        assert_eq!(block.violation, ContentViolation::ContentType);
        // Comparison is case-sensitive, like the reference `in` check.
        assert!(
            decide(&limits, None, Some("Application/JSON"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn missing_content_type_is_blocked_by_an_allowed_list() {
        let limits = ContentLimits {
            max_request_size: None,
            allowed_content_types: Some(vec!["application/json".to_owned()]),
        };
        let block = decide(&limits, None, None).unwrap().expect("no header");
        assert_eq!(block.status, 415);
        assert_eq!(block.reason, "Invalid content type: ");
        // The empty-string media type only passes if a route allows it.
        let limits = ContentLimits {
            max_request_size: None,
            allowed_content_types: Some(vec![String::new()]),
        };
        assert!(decide(&limits, None, None).unwrap().is_none());
    }

    #[test]
    fn size_block_wins_over_the_type_block() {
        let limits = json_only(10);
        let block = decide(&limits, Some("11"), Some("text/plain"))
            .unwrap()
            .expect("blocked");
        assert_eq!(block.violation, ContentViolation::MaxRequestSize);
        assert_eq!(block.status, 413);
        // Under the size limit the type check answers.
        let block = decide(&limits, Some("10"), Some("text/plain"))
            .unwrap()
            .expect("blocked");
        assert_eq!(block.violation, ContentViolation::ContentType);
        assert_eq!(block.status, 415);
    }

    #[test]
    fn media_type_cuts_at_the_first_separator() {
        assert_eq!(
            media_type("application/json; charset=utf-8"),
            "application/json"
        );
        assert_eq!(media_type("application/json"), "application/json");
        assert_eq!(media_type(""), "");
        assert_eq!(media_type(";a"), "");
        assert_eq!(media_type("text/plain;;a=b"), "text/plain");
    }
}
