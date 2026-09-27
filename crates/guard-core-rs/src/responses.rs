//! The reference custom-error and block-hook surfaces
//! (`guard_core/core/responses/factory.py` and
//! `guard_core/_utils/block_events.py`).
//!
//! - [`CustomErrorResponses`] maps a status code to a message that
//!   replaces the family default body for that status
//!   (`ErrorResponseFactory.create_error_response`'s
//!   `custom_error_responses.get(status_code, default_message)`); a
//!   status without an entry keeps the family default byte for byte.
//! - [`OnBlockHook`] is the reference `on_block` callback: fired exactly
//!   once per blocked or passive-mode-flagged request with the payload
//!   keys the reference builds (`check_name`, `reason`, `trigger_info`,
//!   `passive_mode`, `client_ip`, `path` (redacted), `method`,
//!   `status_code`, `None` on the passive path where no response is ever
//!   sent). Never fired for the excluded check names
//!   [`ON_BLOCK_EXCLUDED_CHECK_NAMES`] (application-authored checks and
//!   the HTTPS redirect, which is not a block). A raising callback is
//!   caught and dropped, never propagated.
//!
//! # Example
//!
//! ```
//! use std::collections::HashMap;
//! use std::sync::{Arc, Mutex};
//!
//! use guard_core_rs::responses::{
//!     build_block_payload, fire_block_hook, resolve_error_body, BlockPayload,
//!     OnBlockHook, ON_BLOCK_EXCLUDED_CHECK_NAMES,
//! };
//! use guard_core_rs::tower::StageResponse;
//! use http::StatusCode;
//!
//! let mut custom = HashMap::new();
//! custom.insert(429_u16, "Slow down".to_owned());
//!
//! let body = resolve_error_body(&custom, 429, "Too many requests");
//! assert_eq!(body, "Slow down");
//!
//! let seen: Arc<Mutex<Vec<BlockPayload>>> = Arc::new(Mutex::new(Vec::new()));
//! let sink = seen.clone();
//! let hook: OnBlockHook = Arc::new(move |payload: &BlockPayload| {
//!     sink.lock().expect("sink").push(payload.clone());
//! });
//! let payload = build_block_payload(
//!     "rate_limit",
//!     "Rate limit exceeded",
//!     "",
//!     false,
//!     "192.0.2.1",
//!     "/login?token=abc",
//!     "GET",
//!     Some(429),
//!     &Default::default(),
//! );
//! fire_block_hook(Some(&hook), &payload);
//! assert_eq!(seen.lock().expect("sink").len(), 1);
//! ```

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use crate::redact::{SensitiveNames, redact_url_for_display};

/// The check names the reference never fires the hook for
/// (`ON_BLOCK_EXCLUDED_CHECK_NAMES`): the two application-authored checks
/// and the HTTPS redirect.
pub const ON_BLOCK_EXCLUDED_CHECK_NAMES: [&str; 3] =
    ["custom_request", "custom_validators", "https_enforcement"];

/// The reference `SecurityConfig.custom_error_responses` map: status code
/// to message body override.
pub type CustomErrorResponses = HashMap<u16, String>;

/// Resolve the body for one status: the custom message when configured,
/// else the family default (`custom_error_responses.get(status_code,
/// default_message)`).
#[must_use]
pub fn resolve_error_body(custom: &CustomErrorResponses, status: u16, default: &str) -> String {
    custom
        .get(&status)
        .cloned()
        .unwrap_or_else(|| default.to_owned())
}

/// The reference block payload, key for key
/// (`build_block_payload`). `path` arrives pre-redacted;
/// `status_code` is `None` on the passive-mode path, where no response is
/// ever sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPayload {
    /// The emitting check (`rate_limit`, `ip_security`, ...).
    pub check_name: String,
    /// Why, the reference reason string.
    pub reason: String,
    /// The trigger description when the check carries one.
    pub trigger_info: String,
    /// Whether the pipeline runs in passive (log-only) mode.
    pub passive_mode: bool,
    /// The resolved client identity.
    pub client_ip: String,
    /// The redacted request path.
    pub path: String,
    /// The HTTP method.
    pub method: String,
    /// The block answer's status, `None` on the passive path.
    pub status_code: Option<u16>,
}

/// The `on_block` callback type: sync, best-effort, never fatal.
pub type OnBlockHook = Arc<dyn Fn(&BlockPayload) + Send + Sync>;

/// Build the reference payload: the path runs through the redaction with
/// the merged sensitive sets (`redact_url_for_display`), the client IP is
/// the caller-resolved canonical identity.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_block_payload(
    check_name: &str,
    reason: &str,
    trigger_info: &str,
    passive_mode: bool,
    client_ip: &str,
    path: &str,
    method: &str,
    status_code: Option<u16>,
    sensitive: &SensitiveNames,
) -> BlockPayload {
    BlockPayload {
        check_name: check_name.to_owned(),
        reason: reason.to_owned(),
        trigger_info: trigger_info.to_owned(),
        passive_mode,
        client_ip: client_ip.to_owned(),
        path: redact_url_for_display(path, sensitive),
        method: method.to_owned(),
        status_code,
    }
}

/// Fire the hook for one block (`fire_block_hook`): skipped for the
/// excluded check names, one panic per callback swallowed and dropped
/// (the reference catches, logs, and never propagates).
pub fn fire_block_hook(hook: Option<&OnBlockHook>, payload: &BlockPayload) {
    let Some(hook) = hook else {
        return;
    };
    if ON_BLOCK_EXCLUDED_CHECK_NAMES.contains(&payload.check_name.as_str()) {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| hook(payload)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    fn names() -> SensitiveNames {
        SensitiveNames::default()
    }

    #[test]
    fn custom_bodies_override_the_default_only_when_configured() {
        let mut custom = CustomErrorResponses::new();
        custom.insert(403, "Nope".to_owned());
        assert_eq!(
            resolve_error_body(&custom, 403, "IP address banned"),
            "Nope"
        );
        assert_eq!(
            resolve_error_body(&custom, 429, "Too many requests"),
            "Too many requests"
        );
    }

    #[test]
    fn payload_matches_the_reference_keys_and_redacts_the_path() {
        let payload = build_block_payload(
            "rate_limit",
            "Rate limit exceeded",
            "",
            false,
            "192.0.2.1",
            "/login?token=abc",
            "GET",
            Some(429),
            &names(),
        );
        assert_eq!(payload.check_name, "rate_limit");
        assert_eq!(payload.path, "/login?token=[REDACTED]");
        assert_eq!(payload.status_code, Some(429));
        assert!(!payload.passive_mode);
    }

    #[test]
    fn passive_payloads_carry_no_status() {
        let payload = build_block_payload(
            "suspicious_activity",
            "Suspicious activity detected",
            "trigger",
            true,
            "192.0.2.1",
            "/x",
            "GET",
            None,
            &names(),
        );
        assert_eq!(payload.status_code, None);
        assert!(payload.passive_mode);
    }

    #[test]
    fn excluded_check_names_never_fire() {
        let seen = Arc::new(Mutex::new(0_usize));
        let sink = seen.clone();
        let hook: OnBlockHook = Arc::new(move |_| {
            *sink.lock().expect("sink") += 1;
        });
        for name in ON_BLOCK_EXCLUDED_CHECK_NAMES {
            let payload =
                build_block_payload(name, "r", "", false, "ip", "/p", "GET", Some(403), &names());
            fire_block_hook(Some(&hook), &payload);
        }
        assert_eq!(*seen.lock().expect("sink"), 0);
    }

    #[test]
    fn excluded_set_matches_the_reference() {
        let expected: HashSet<&str> = ["custom_request", "custom_validators", "https_enforcement"]
            .into_iter()
            .collect();
        assert_eq!(
            ON_BLOCK_EXCLUDED_CHECK_NAMES
                .iter()
                .copied()
                .collect::<HashSet<&str>>(),
            expected
        );
    }

    #[test]
    fn a_raising_hook_does_not_propagate() {
        let hook: OnBlockHook = Arc::new(|_: &BlockPayload| panic!("hook blew up"));
        let payload = build_block_payload(
            "rate_limit",
            "r",
            "",
            false,
            "ip",
            "/p",
            "GET",
            Some(429),
            &names(),
        );
        fire_block_hook(Some(&hook), &payload);
    }

    #[test]
    fn no_hook_is_a_no_op() {
        let payload = build_block_payload(
            "rate_limit",
            "r",
            "",
            false,
            "ip",
            "/p",
            "GET",
            Some(429),
            &names(),
        );
        fire_block_hook(None, &payload);
    }
}
