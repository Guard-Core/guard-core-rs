//! The `log_activity` port (`guard_core/_utils/request_logging.py`): the
//! guard log lines with the reference wording, the redaction sets, the
//! per-check log levels, and the `muted_check_logs` mute list.
//!
//! The Rust facade owns no logger: [`log_activity`] composes the exact
//! reference message and hands it back (`None` when the reference would
//! log nothing: level `None` or a muted check). Hosts emit the line
//! through their own logging stack, or feed the composed value to
//! [`SecurityEventBus`](crate::events::SecurityEventBus) handlers in
//! tests. The message shapes, byte for byte:
//!
//! - `request`: `Request from {ip}: {method} {url} - Headers: {headers}`
//! - `suspicious` (active):
//!   `Suspicious activity detected from {ip}: {method} {url} - Reason: {reason} - Headers: {headers}`
//! - `suspicious` (passive):
//!   `[PASSIVE MODE] Penetration attempt detected from {ip}: {method} {url} - Trigger: {trigger} - Headers: {headers}`
//!   (no `Trigger:` segment when `trigger_info` is empty)
//! - any other `log_type`: `{Type} from {ip}: {method} {url} - Details: {reason} - Headers: {headers}`
//!
//! URL and headers run through [`crate::redact`] with the merged
//! sensitive-name sets before composition.
//!
//! # Example
//!
//! ```
//! use guard_core_rs::logging::{log_activity, LogLevel, LogType};
//! use guard_core_rs::redact::SensitiveNames;
//!
//! let line = log_activity(
//!     LogType::Suspicious,
//!     Some(LogLevel::Warning),
//!     "Suspicious activity detected for IP: 192.0.2.1 - sqli",
//!     Some("192.0.2.1"),
//!     Some("POST"),
//!     Some("/login?token=abc"),
//!     None,
//!     false,
//!     "",
//!     None,
//!     None,
//!     &SensitiveNames::default(),
//! )
//! .expect("logged");
//!
//! assert!(line.starts_with("Suspicious activity detected from 192.0.2.1:"));
//! ```

use std::collections::HashSet;

use crate::redact::{SensitiveNames, redact_headers, redact_url_for_display};

/// The reference log levels (`Literal["INFO", "DEBUG", "WARNING",
/// "ERROR", "CRITICAL"]`); `None` (the `log_request_level` default) means
/// the reference logs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// `INFO`.
    Info,
    /// `DEBUG`.
    Debug,
    /// `WARNING`.
    Warning,
    /// `ERROR`.
    Error,
    /// `CRITICAL`.
    Critical,
}

impl LogLevel {
    /// The level's name as the reference spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Critical => "CRITICAL",
        }
    }
}

/// The `log_type` argument: `request`, `suspicious`, or anything else
/// (the generic `{Type} from` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogType {
    /// `request`.
    Request,
    /// `suspicious`.
    Suspicious,
    /// Any other `log_type` string (`blocked`, `banned`, ...), capitalized
    /// into the generic shape.
    Other(String),
}

impl LogType {
    /// The reference `log_type` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Request => "request",
            Self::Suspicious => "suspicious",
            Self::Other(value) => value,
        }
    }
}

/// The pieces of a request the guard log lines carry, redacted on the way
/// in (`_extract_request_context`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogContext {
    /// The client IP: the cached `state.client_ip` when the pipeline
    /// resolved one, else the canonical peer, else `unknown` (the
    /// reference `UNKNOWN_CLIENT_IDENTITY`).
    pub client_ip: Option<String>,
    /// The HTTP method.
    pub method: Option<String>,
    /// The full URL, redacted through [`redact_url_for_display`].
    pub url: Option<String>,
    /// The header map, redacted through [`redact_headers`].
    pub headers: Vec<(String, String)>,
}

/// The `log_activity` entry point. Returns the composed line when the
/// reference would log (level set, check not muted), `None` otherwise.
///
/// The `level` argument is `None` for "no log" (the reference's
/// `level=None`), so it takes `Option<LogLevel>`.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::implicit_hasher)]
pub fn log_activity(
    log_type: LogType,
    level: Option<LogLevel>,
    reason: &str,
    client_ip: Option<&str>,
    method: Option<&str>,
    url: Option<&str>,
    headers: Option<&[(&str, &str)]>,
    passive_mode: bool,
    trigger_info: &str,
    check_name: Option<&str>,
    muted_check_logs: Option<&HashSet<String>>,
    sensitive: &SensitiveNames,
) -> Option<String> {
    // muted_check_logs: the reference returns before composing.
    if let Some(name) = check_name
        && muted_check_logs.is_some_and(|muted| muted.contains(name))
    {
        return None;
    }
    let level = level?;

    let ip = client_ip.unwrap_or("unknown");
    let redacted_url = url.map(|value| redact_url_for_display(value, sensitive));
    let redacted_headers = headers.map(|values| redact_headers(values, sensitive));

    let details = match log_type {
        LogType::Request => format!(
            "Request from {ip}: {} {}",
            method.unwrap_or_default(),
            redacted_url.as_deref().unwrap_or_default()
        ),
        LogType::Suspicious => {
            if passive_mode {
                format!(
                    "[PASSIVE MODE] Penetration attempt detected from {ip}: {} {}",
                    method.unwrap_or_default(),
                    redacted_url.as_deref().unwrap_or_default()
                )
            } else {
                format!(
                    "Suspicious activity detected from {ip}: {} {}",
                    method.unwrap_or_default(),
                    redacted_url.as_deref().unwrap_or_default()
                )
            }
        }
        LogType::Other(ref kind) => format!(
            "{} from {ip}: {} {}",
            capitalize(kind),
            method.unwrap_or_default(),
            redacted_url.as_deref().unwrap_or_default()
        ),
    };

    let reason_message = match log_type {
        LogType::Request => {
            format!("Headers: {}", display_headers(redacted_headers.as_ref()))
        }
        LogType::Suspicious => {
            if passive_mode {
                let mut message = String::new();
                if !trigger_info.is_empty() {
                    message.push_str("Trigger: ");
                    message.push_str(trigger_info);
                    message.push_str(" - ");
                }
                message.push_str("Headers: ");
                message.push_str(&display_headers(redacted_headers.as_ref()));
                message
            } else {
                format!(
                    "Reason: {reason} - Headers: {}",
                    display_headers(redacted_headers.as_ref())
                )
            }
        }
        LogType::Other(_) => format!(
            "Details: {reason} - Headers: {}",
            display_headers(redacted_headers.as_ref())
        ),
    };

    let _ = level; // The caller owns emission; the level rides the enum.
    Some(format!("{details} - {reason_message}"))
}

fn display_headers(headers: Option<&Vec<(String, String)>>) -> String {
    headers.map_or_else(
        || "{}".to_owned(),
        |pairs| {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(key, value)| format!("'{key}': '{value}'"))
                .collect();
            format!("{{{}}}", inner.join(", "))
        },
    )
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::SensitiveNames;

    fn names() -> SensitiveNames {
        SensitiveNames::default()
    }

    #[test]
    fn request_shape_matches_the_reference() {
        let line = log_activity(
            LogType::Request,
            Some(LogLevel::Info),
            "",
            Some("192.0.2.1"),
            Some("GET"),
            Some("/login?token=abc"),
            Some(&[("Authorization", "Bearer x")]),
            false,
            "",
            None,
            None,
            &names(),
        )
        .expect("logged");
        assert_eq!(
            line,
            "Request from 192.0.2.1: GET /login?token=[REDACTED] - Headers: \
             {'Authorization': '[REDACTED]'}"
        );
    }

    #[test]
    fn suspicious_active_shape_matches_the_reference() {
        let line = log_activity(
            LogType::Suspicious,
            Some(LogLevel::Warning),
            "Suspicious activity detected for IP: 192.0.2.1 - sqli",
            Some("192.0.2.1"),
            Some("POST"),
            Some("/q"),
            None,
            false,
            "",
            None,
            None,
            &names(),
        )
        .expect("logged");
        assert_eq!(
            line,
            "Suspicious activity detected from 192.0.2.1: POST /q - Reason: \
             Suspicious activity detected for IP: 192.0.2.1 - sqli - Headers: {}"
        );
    }

    #[test]
    fn suspicious_passive_shape_matches_the_reference() {
        let line = log_activity(
            LogType::Suspicious,
            Some(LogLevel::Warning),
            "ignored in passive mode",
            Some("192.0.2.1"),
            Some("GET"),
            Some("/q"),
            None,
            true,
            "sqli in query",
            None,
            None,
            &names(),
        )
        .expect("logged");
        assert_eq!(
            line,
            "[PASSIVE MODE] Penetration attempt detected from 192.0.2.1: GET /q - \
             Trigger: sqli in query - Headers: {}"
        );
    }

    #[test]
    fn passive_without_trigger_skips_the_trigger_segment() {
        let line = log_activity(
            LogType::Suspicious,
            Some(LogLevel::Warning),
            "",
            Some("192.0.2.1"),
            Some("GET"),
            Some("/q"),
            None,
            true,
            "",
            None,
            None,
            &names(),
        )
        .expect("logged");
        assert!(line.ends_with("/q - Headers: {}"));
    }

    #[test]
    fn generic_shape_capitalizes_the_log_type() {
        let line = log_activity(
            LogType::Other("blocked".to_owned()),
            Some(LogLevel::Error),
            "cloud provider",
            Some("192.0.2.1"),
            Some("GET"),
            Some("/"),
            None,
            false,
            "",
            None,
            None,
            &names(),
        )
        .expect("logged");
        assert!(line.starts_with("Blocked from 192.0.2.1: GET / - Details: cloud provider"));
    }

    #[test]
    fn muted_check_logs_suppress_the_line() {
        let muted = HashSet::from(["rate_limit".to_owned()]);
        let line = log_activity(
            LogType::Suspicious,
            Some(LogLevel::Warning),
            "rate limit",
            Some("192.0.2.1"),
            Some("GET"),
            Some("/"),
            None,
            false,
            "",
            Some("rate_limit"),
            Some(&muted),
            &names(),
        );
        assert!(line.is_none());
    }

    #[test]
    fn a_none_level_logs_nothing() {
        let line = log_activity(
            LogType::Request,
            None,
            "",
            Some("192.0.2.1"),
            Some("GET"),
            Some("/"),
            None,
            false,
            "",
            None,
            None,
            &names(),
        );
        assert!(line.is_none());
    }

    #[test]
    fn unknown_ip_falls_back_like_the_reference() {
        let line = log_activity(
            LogType::Request,
            Some(LogLevel::Debug),
            "",
            None,
            Some("GET"),
            Some("/"),
            None,
            false,
            "",
            None,
            None,
            &names(),
        )
        .expect("logged");
        assert!(line.starts_with("Request from unknown:"));
    }
}
