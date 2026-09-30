//! The request-logging pass: the reference pipeline's fourth check.
//!
//! This is the Rust family's port of
//! `guard_core/core/checks/implementations/request_logging.py`. The check
//! **never blocks**: it logs the request through the reference
//! `log_activity` at `config.log_request_level` (with the check name, the
//! muted set, and the sensitive-field redaction) and returns `None`. The
//! reference only constructs it when the level is set (`applies_to`:
//! `log_request_level is not None`), so an unset level means the check
//! does not exist in the pipeline at all.
//!
//! The engine keeps the check's contract (the name, the never-blocks
//! decision, the construction gate); the line composition lives on the
//! facade stage (`guard_core_rs::request_logging`), which runs the family's
//! `log_activity` shape - the reference's log line text is a `SHOULD`
//! match, and the verdict contract (always `None`) is a `MUST`.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::request_logging::{constructs, decide};
//!
//! // The construction gate: an unset level installs nothing.
//! assert!(!constructs(None));
//! assert!(constructs(Some("INFO")));
//!
//! // The verdict contract: the check never blocks.
//! assert!(decide().is_none());
//! ```

/// The check's stable name (`check_name`).
pub const REQUEST_LOGGING_CHECK_NAME: &str = "request_logging";

/// The construction gate (`applies_to`): the check exists only when
/// `config.log_request_level` is set. The level is the reference's
/// `"INFO" | "DEBUG" | "WARNING" | "ERROR" | "CRITICAL"` literal.
#[must_use]
pub const fn constructs(log_request_level: Option<&str>) -> bool {
    log_request_level.is_some()
}

/// The check body: it never blocks, whatever the request carries.
#[must_use]
pub const fn decide() -> Option<core::convert::Infallible> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_mirrors_the_reference_applies_to() {
        assert!(!constructs(None));
        for level in ["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] {
            assert!(constructs(Some(level)));
        }
    }

    #[test]
    fn the_check_never_blocks() {
        assert!(decide().is_none());
        assert_eq!(REQUEST_LOGGING_CHECK_NAME, "request_logging");
    }
}
