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
use std::time::{SystemTime, UNIX_EPOCH};

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

/// The python-logging timestamp shape the reference formatters share
/// (`Formatter.formatTime` default, `2026-10-06 12:34:56,789`).
#[must_use]
pub fn asctime(at: SystemTime) -> String {
    let (secs, millis) = match at.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs().cast_signed(), duration.subsec_millis()),
        Err(error) => (-(error.duration().as_secs().cast_signed()), 0),
    };
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
        + format!(",{millis:03}").as_str()
}

/// The `logging_utils.py` `JsonFormatter` record: exactly four fields in
/// the reference key order.
///
/// `timestamp` (the asctime shape), `level` (uppercase), `logger`
/// (channel), `message`. Hosts that want the exact reference wire shape
/// feed this string to their logging stack instead of configuring a JSON
/// log subscriber (the `setup_custom_logging` parity stays a host concern:
/// the Rust facade owns no logging registry, the same split the `log`
/// crate calls keep everywhere else).
///
/// # Example
///
/// ```
/// use std::time::{Duration, SystemTime};
///
/// use guard_core_rs::logging::{LogLevel, json_record};
///
/// let at = SystemTime::UNIX_EPOCH + Duration::from_millis(86_400_000 + 1_234);
/// let line = json_record(LogLevel::Warning, "blocked request", at);
/// assert_eq!(
///     line,
///     r#"{"timestamp":"1970-01-02 00:00:01,234","level":"WARNING","logger":"guard_core","message":"blocked request"}"#
/// );
/// ```
#[must_use]
pub fn json_record(level: LogLevel, message: &str, at: SystemTime) -> String {
    json_record_for(level, message, at, DEFAULT_LOG_CHANNEL)
}

/// The reference `_create_formatter` text layout:
/// `[%(name)s] %(asctime)s - %(levelname)s - %(message)s`.
///
/// # Example
///
/// ```
/// use std::time::{Duration, SystemTime};
///
/// use guard_core_rs::logging::{LogLevel, text_record};
///
/// let at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_234);
/// let line = text_record(LogLevel::Info, "hello", at);
/// assert_eq!(line, "[guard_core] 1970-01-01 00:00:01,234 - INFO - hello");
/// ```
#[must_use]
pub fn text_record(level: LogLevel, message: &str, at: SystemTime) -> String {
    text_record_for(level, message, at, DEFAULT_LOG_CHANNEL)
}

/// The default channel (`logging.getLogger("guard_core")`).
pub const DEFAULT_LOG_CHANNEL: &str = "guard_core";

/// [`json_record`] over an explicit channel.
#[must_use]
pub fn json_record_for(level: LogLevel, message: &str, at: SystemTime, channel: &str) -> String {
    // The reference json.dumps default escapes non-ASCII; serde_json's
    // to_string does the same for control characters, and the record is
    // always a string-built object so the encode cannot fail.
    serde_json::json!({
        "timestamp": asctime(at),
        "level": level.as_str(),
        "logger": channel,
        "message": message,
    })
    .to_string()
}

/// [`text_record`] over an explicit channel.
#[must_use]
pub fn text_record_for(level: LogLevel, message: &str, at: SystemTime, channel: &str) -> String {
    format!(
        "[{channel}] {} - {} - {}",
        asctime(at),
        level.as_str(),
        message
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::SensitiveNames;
    use std::time::Duration;

    fn names() -> SensitiveNames {
        SensitiveNames::default()
    }

    #[test]
    fn the_json_record_carries_the_reference_fields_in_order() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_millis(86_400_000 + 1_234);
        let line = json_record(LogLevel::Warning, "blocked request", at);
        assert_eq!(
            line,
            r#"{"timestamp":"1970-01-02 00:00:01,234","level":"WARNING","logger":"guard_core","message":"blocked request"}"#
        );
        let decoded: serde_json::Value = serde_json::from_str(&line).expect("json");
        let keys: Vec<&str> = decoded
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["timestamp", "level", "logger", "message"]);
    }

    #[test]
    fn the_json_record_escapes_like_the_reference_dumps() {
        let at = SystemTime::UNIX_EPOCH;
        let line = json_record(LogLevel::Info, "line1\nline2 \"quoted\"", at);
        let decoded: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(decoded["message"], "line1\nline2 \"quoted\"");
        assert_eq!(decoded["level"], "INFO");
    }

    #[test]
    fn the_text_record_mirrors_the_reference_layout() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_234);
        assert_eq!(
            text_record(LogLevel::Info, "hello", at),
            "[guard_core] 1970-01-01 00:00:01,234 - INFO - hello"
        );
        assert_eq!(
            text_record(LogLevel::Critical, "boom", at),
            "[guard_core] 1970-01-01 00:00:01,234 - CRITICAL - boom"
        );
    }

    #[test]
    fn the_explicit_channel_overrides_flow_through_both_record_shapes() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_millis(2_000);
        assert_eq!(
            text_record_for(LogLevel::Debug, "dbg", at, "checkout"),
            "[checkout] 1970-01-01 00:00:02,000 - DEBUG - dbg"
        );
        let line = json_record_for(LogLevel::Error, "err", at, "checkout");
        let decoded: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(decoded["logger"], "checkout");
        assert_eq!(decoded["timestamp"], "1970-01-01 00:00:02,000");
    }

    #[test]
    fn the_asctime_shape_carries_millisecond_precision() {
        let at = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 999_000_000);
        assert_eq!(asctime(at), "2023-11-14 22:13:20,999");
    }

    #[test]
    fn a_pre_epoch_clock_degrades_to_a_negative_second_without_panicking() {
        let before = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch instant");
        let line = asctime(before);
        assert!(line.ends_with(",000"), "{line}");
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

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn log_levels_render_the_reference_names() {
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Warning.as_str(), "WARNING");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn log_types_render_request_suspicious_and_the_generic_shape() {
        assert_eq!(LogType::Request.as_str(), "request");
        assert_eq!(LogType::Suspicious.as_str(), "suspicious");
        assert_eq!(LogType::Other("blocked".to_owned()).as_str(), "blocked");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn log_activity_composes_every_level_type_and_mute_shape() {
        use std::collections::HashSet;
        let sensitive = SensitiveNames::default();
        let headers = [("authorization", "Bearer secret")];

        // every level renders its name
        for level in [
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Warning,
            LogLevel::Error,
            LogLevel::Critical,
        ] {
            let line = log_activity(
                LogType::Request,
                Some(level),
                "ok",
                Some("1.2.3.4"),
                Some("GET"),
                Some("/x?token=a"),
                Some(&headers),
                false,
                "",
                None,
                None,
                &sensitive,
            )
            .expect("logged");
            assert!(line.contains("Request from 1.2.3.4"), "unexpected: {line}");
            assert!(line.contains("token=[REDACTED]"));
        }

        // a muted check returns None before composing
        let mut muted = HashSet::new();
        muted.insert("rate_limit".to_owned());
        assert!(
            log_activity(
                LogType::Suspicious,
                Some(LogLevel::Warning),
                "why",
                None,
                None,
                None,
                None,
                true,
                "trigger",
                Some("rate_limit"),
                Some(&muted),
                &sensitive,
            )
            .is_none()
        );

        // a None level means no log
        assert!(
            log_activity(
                LogType::Request,
                None,
                "",
                None,
                None,
                None,
                None,
                false,
                "",
                None,
                None,
                &sensitive,
            )
            .is_none()
        );

        // the suspicious shape (passive and active)
        let passive = log_activity(
            LogType::Suspicious,
            Some(LogLevel::Warning),
            "why",
            Some("1.2.3.4"),
            Some("GET"),
            Some("/x"),
            None,
            true,
            "trigger",
            None,
            None,
            &sensitive,
        )
        .expect("logged");
        assert!(passive.contains("[PASSIVE MODE] Penetration attempt detected"));

        let active = log_activity(
            LogType::Suspicious,
            Some(LogLevel::Warning),
            "why",
            Some("1.2.3.4"),
            Some("GET"),
            Some("/x"),
            None,
            false,
            "trigger",
            None,
            None,
            &sensitive,
        )
        .expect("logged");
        assert!(active.contains("Suspicious activity detected from 1.2.3.4"));

        // the generic Other shape capitalizes the type
        let other = log_activity(
            LogType::Other("banned".to_owned()),
            Some(LogLevel::Error),
            "why",
            Some("1.2.3.4"),
            Some("GET"),
            Some("/x"),
            None,
            false,
            "trigger",
            None,
            None,
            &sensitive,
        )
        .expect("logged");
        assert!(other.contains("Banned from 1.2.3.4"), "unexpected: {other}");
    }
}
