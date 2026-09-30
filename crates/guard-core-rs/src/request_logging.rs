//! The request-logging pipeline stage: the reference engine's fourth
//! check, which never blocks.
//!
//! The decision core is [`guard_core_engine::request_logging`]; this stage
//! composes the reference `log_activity` line the check emits: the
//! `request` log type at `config.log_request_level`, with the check name,
//! the muted set, and the sensitive-field redaction. The stage never
//! answers a block - the reference check always returns `None`.
//!
//! ```text
//! level unset:      the stage does not exist (the reference applies_to gate)
//! level set:        compose the "Request from {ip}: {method} {url}" line
//!                   at that level (redacted, muted-set aware), pass on
//! ```
//!
//! # Example
//!
//! ```
//! use guard_core_rs::logging::LogLevel;
//! use guard_core_rs::request_logging::{RequestLoggingStage, RequestLoggingStageConfig};
//!
//! let stage = RequestLoggingStage::new(RequestLoggingStageConfig {
//!     log_request_level: Some(LogLevel::Info),
//!     ..RequestLoggingStageConfig::default()
//! });
//!
//! let line = stage
//!     .compose(Some("192.0.2.9"), Some("GET"), Some("/public/x"), None)
//!     .expect("composed");
//! assert!(line.contains("Request from 192.0.2.9"));
//!
//! // The stage never blocks, whatever the request carries.
//! assert!(guard_core_engine::request_logging::decide().is_none());
//! ```

use guard_core_engine::request_logging::REQUEST_LOGGING_CHECK_NAME;

use crate::logging::{LogLevel, LogType, log_activity};
use crate::redact::SensitiveNames;

/// The stage's knobs (`SecurityConfig.log_request_level`,
/// `.muted_check_logs`, and the merged `log_sensitive_*` redaction sets).
#[derive(Debug, Clone, Default)]
pub struct RequestLoggingStageConfig {
    /// `log_request_level`: the level the request line logs at; `None`
    /// means the stage does not exist in the pipeline.
    pub log_request_level: Option<LogLevel>,
    /// `muted_check_logs`: check names suppressed from pipeline logging.
    pub muted_check_logs: Option<std::collections::HashSet<String>>,
    /// The merged sensitive-name sets for the redaction.
    pub sensitive: SensitiveNames,
}

/// The request-logging stage: compose-only, never blocks.
#[derive(Debug, Clone, Default)]
pub struct RequestLoggingStage {
    config: RequestLoggingStageConfig,
}

impl RequestLoggingStage {
    /// Build the stage over `config`.
    #[must_use]
    pub const fn new(config: RequestLoggingStageConfig) -> Self {
        Self { config }
    }

    /// The reference construction gate: `log_request_level is not None`.
    #[must_use]
    pub const fn exists(&self) -> bool {
        self.config.log_request_level.is_some()
    }

    /// Compose the reference request log line (`log_activity` with the
    /// `request` log type at the configured level): `Some(line)` is what
    /// the host logs; `None` mirrors the reference composing nothing (an
    /// unset level, or the check name muted).
    #[must_use]
    pub fn compose(
        &self,
        client_ip: Option<&str>,
        method: Option<&str>,
        url: Option<&str>,
        headers: Option<&[(&str, &str)]>,
    ) -> Option<String> {
        log_activity(
            LogType::Request,
            self.config.log_request_level,
            "",
            client_ip,
            method,
            url,
            headers,
            false,
            "",
            Some(REQUEST_LOGGING_CHECK_NAME),
            self.config.muted_check_logs.as_ref(),
            &self.config.sensitive,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_the_reference_request_line_when_the_level_is_set() {
        let stage = RequestLoggingStage::new(RequestLoggingStageConfig {
            log_request_level: Some(LogLevel::Info),
            ..RequestLoggingStageConfig::default()
        });
        assert!(stage.exists());
        let line = stage
            .compose(Some("192.0.2.9"), Some("GET"), Some("/public/x?q=1"), None)
            .expect("composed");
        assert!(line.contains("Request from 192.0.2.9"), "{line}");
        assert!(line.contains("GET"), "{line}");
        assert!(line.contains("/public/x"), "{line}");
    }

    #[test]
    fn an_unset_level_mirrors_the_applies_to_gate() {
        let stage = RequestLoggingStage::new(RequestLoggingStageConfig::default());
        assert!(!stage.exists());
        assert!(
            stage
                .compose(Some("192.0.2.9"), Some("GET"), Some("/"), None)
                .is_none()
        );
        // The engine gate agrees.
        assert!(!guard_core_engine::request_logging::constructs(None));
        assert!(guard_core_engine::request_logging::constructs(Some("INFO")));
    }

    #[test]
    fn a_muted_check_composes_nothing() {
        let mut muted = std::collections::HashSet::new();
        muted.insert(REQUEST_LOGGING_CHECK_NAME.to_owned());
        let stage = RequestLoggingStage::new(RequestLoggingStageConfig {
            log_request_level: Some(LogLevel::Info),
            muted_check_logs: Some(muted),
            ..RequestLoggingStageConfig::default()
        });
        assert!(
            stage
                .compose(Some("192.0.2.9"), Some("GET"), Some("/"), None)
                .is_none()
        );
    }

    #[test]
    fn sensitive_query_parameters_are_redacted() {
        let mut fields = std::collections::HashSet::new();
        fields.insert("token".to_owned());
        let sensitive = SensitiveNames::new(None, Some(&fields), None);
        let stage = RequestLoggingStage::new(RequestLoggingStageConfig {
            log_request_level: Some(LogLevel::Info),
            sensitive,
            ..RequestLoggingStageConfig::default()
        });
        let line = stage
            .compose(
                Some("192.0.2.9"),
                Some("GET"),
                Some("/x?token=secret"),
                None,
            )
            .expect("composed");
        assert!(!line.contains("secret"), "{line}");
    }

    #[test]
    fn the_stage_never_blocks() {
        assert!(guard_core_engine::request_logging::decide().is_none());
    }
}
