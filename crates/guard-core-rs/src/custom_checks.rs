//! The custom function pipeline stage for tower stacks: the reference
//! pipeline's `custom_request` and `custom_validators` checks.
//!
//! The decision core is [`guard_core_engine::custom_checks`]; this stage
//! hosts the function seams the way the reference `SecurityConfig` does:
//! a global `custom_request_check` and per-route `custom_validators`
//! (the reference reads them from `request.state.route_config`).
//!
//! ```text
//! custom_request (global, check 17):
//!   check returns None:        pass
//!   check returns a response:  the response is the answer (the reference
//!                              applies the response modifier and returns
//!                              it; passive mode logs only)
//! custom_validators (route, check 9):
//!   no route list:             pass
//!   validator returns a truthy non-response: pass (log/emit only in the
//!                              reference - it can never block)
//!   validator returns a response: the validator's own response is the
//!                              answer, as-is (never create_error_response)
//! ```
//!
//! Neither check ever fires the `on_block` hook (both are in
//! `ON_BLOCK_EXCLUDED_CHECK_NAMES`), which the family hook already
//! enforces - the stage carries no hook by construction.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_rs::custom_checks::{CustomChecksStage, CustomResponse};
//!
//! let stage = CustomChecksStage::builder()
//!     .custom_request("maintenance_gate", Arc::new(|ctx| {
//!         (ctx.path == "/admin").then(|| CustomResponse { status: Some(503) })
//!     }))
//!     .build();
//!
//! let answer = stage.decide_custom_request("GET", "/admin", None).expect("blocked");
//! assert_eq!(answer.status, Some(503));
//! assert_eq!(answer.function, "maintenance_gate");
//! assert!(stage.decide_custom_request("GET", "/public", None).is_none());
//! ```

use std::sync::Arc;

use crate::event_types::{EVENT_CUSTOM_REQUEST_CHECK, EVENT_DECORATOR_VIOLATION};
use crate::events::{MIDDLEWARE_HANDLER_NAME, SecurityEvent, SecurityEventBus};

pub use guard_core_engine::custom_checks::{
    CUSTOM_REQUEST_CHECK_NAME, CUSTOM_VALIDATORS_CHECK_NAME, CustomRequestContext, CustomRequestFn,
    CustomRequestVerdict, CustomResponse, CustomValidatorsVerdict, ValidatorAnswer, anonymous_name,
    decide_custom_request as engine_custom_request, decide_custom_validators,
};

/// How the stage learns a path's `custom_validators` (the reference reads
/// them from `request.state.route_config`; `None` means the route carries
/// none).
pub type RouteValidatorsResolver =
    Arc<dyn Fn(&str) -> Option<Vec<(String, CustomValidatorFn)>> + Send + Sync>;

/// The validator function type re-exported for resolver authors.
pub use guard_core_engine::custom_checks::CustomValidatorFn as RouteValidatorFn;
use guard_core_engine::custom_checks::CustomValidatorFn;

/// The `custom_request` answer.
///
/// The reference emits `custom_request_check` with the response status
/// (or `"unknown"`) and the function name (or `"anonymous"`), then
/// applies the modifier and returns the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRequestAnswer {
    /// The response's status, `None` for the `"unknown"` arm.
    pub status: Option<u16>,
    /// The registered function name.
    pub function: String,
}

/// The `custom_validators` answer: the validator's own response (as-is,
/// never a custom-error shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorFailure {
    /// The validator's blocking response.
    pub status: Option<u16>,
    /// The validator's registered name.
    pub validator: String,
}

/// The custom function stage.
#[derive(Clone, Default)]
pub struct CustomChecksStage {
    custom_request: Option<(String, CustomRequestFn)>,
    validators_resolver: Option<RouteValidatorsResolver>,
    passive_mode: bool,
    events: Option<Arc<SecurityEventBus>>,
}

impl std::fmt::Debug for CustomChecksStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomChecksStage")
            .field("passive_mode", &self.passive_mode)
            .finish_non_exhaustive()
    }
}

/// Builder for [`CustomChecksStage`].
#[derive(Default)]
pub struct CustomChecksStageBuilder {
    custom_request: Option<(String, CustomRequestFn)>,
    validators_resolver: Option<RouteValidatorsResolver>,
    passive_mode: bool,
    events: Option<Arc<SecurityEventBus>>,
}

impl CustomChecksStage {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> CustomChecksStageBuilder {
        CustomChecksStageBuilder::default()
    }

    /// The `custom_request` check (17): the global function runs once.
    /// `None` passes; `Some` is the returned response. Passive mode
    /// observes only (the reference returns `None` but still emits).
    #[must_use]
    pub fn decide_custom_request(
        &self,
        method: &str,
        path: &str,
        client_ip: Option<&str>,
    ) -> Option<CustomRequestAnswer> {
        let Some((name, check)) = &self.custom_request else {
            return None;
        };
        let ctx = CustomRequestContext {
            method,
            path,
            client_ip,
        };
        match engine_custom_request(check, name, &ctx) {
            CustomRequestVerdict::Allowed => None,
            CustomRequestVerdict::Blocked { status, function } => {
                // The reference emits the check event in both modes,
                // flipping the action under passive mode, before the
                // passive branch skips the block.
                self.observe_custom_request(&function, status, path, method, client_ip);
                if self.passive_mode {
                    None
                } else {
                    Some(CustomRequestAnswer { status, function })
                }
            }
        }
    }

    /// The `custom_validators` check (9): the route's validators run in
    /// order, first truthy answer wins. A truthy non-response logs in the
    /// reference but never blocks; a response blocks with itself.
    #[must_use]
    pub fn decide_custom_validators(
        &self,
        path: &str,
        method: &str,
        client_ip: Option<&str>,
    ) -> Option<ValidatorFailure> {
        let Some(resolver) = &self.validators_resolver else {
            return None;
        };
        let validators = resolver(path)?;
        let ctx = CustomRequestContext {
            method,
            path,
            client_ip,
        };
        match decide_custom_validators(&validators, &ctx) {
            CustomValidatorsVerdict::Allowed => None,
            CustomValidatorsVerdict::Failed { block, validator } => {
                // The truthy-non-response arm logs but never blocks, and
                // passive mode never blocks either (the reference returns
                // the validator's response only in active mode) - but the
                // decorator violation is emitted in both modes either way.
                self.observe_custom_validation(&validator, path, method, client_ip);
                let response = block?;
                if self.passive_mode {
                    None
                } else {
                    Some(ValidatorFailure {
                        status: response.status,
                        validator,
                    })
                }
            }
        }
    }

    /// Whether the mode observes without blocking.
    #[must_use]
    pub const fn passive_mode(&self) -> bool {
        self.passive_mode
    }

    /// The `custom_request` emission (`send_middleware_event` with
    /// `EVENT_CUSTOM_REQUEST_CHECK`): the response status (or
    /// `"unknown"`) and the check function's registered name.
    fn observe_custom_request(
        &self,
        function: &str,
        status: Option<u16>,
        path: &str,
        method: &str,
        client_ip: Option<&str>,
    ) {
        let Some(bus) = &self.events else {
            return;
        };
        let mut event = SecurityEvent::new(
            EVENT_CUSTOM_REQUEST_CHECK,
            client_ip.unwrap_or_default(),
            if self.passive_mode {
                "logged_only"
            } else {
                "request_blocked"
            },
            "Custom request check returned blocking response",
            MIDDLEWARE_HANDLER_NAME,
        );
        event.endpoint = Some(path.to_owned());
        event.method = Some(method.to_owned());
        event.metadata.insert(
            String::from("response_status"),
            status.map_or_else(
                || serde_json::json!("unknown"),
                |code| serde_json::json!(code),
            ),
        );
        event
            .metadata
            .insert(String::from("check_function"), serde_json::json!(function));
        bus.send_event(&event);
    }

    /// The `custom_validators` emission (`emit_decorator_event`): the
    /// `decorator_violation` with `decorator_type` `content_filtering`,
    /// `violation_type` `custom_validation`, and the validator's name.
    fn observe_custom_validation(
        &self,
        validator: &str,
        path: &str,
        method: &str,
        client_ip: Option<&str>,
    ) {
        let Some(bus) = &self.events else {
            return;
        };
        let mut event = SecurityEvent::new(
            EVENT_DECORATOR_VIOLATION,
            client_ip.unwrap_or_default(),
            if self.passive_mode {
                "logged_only"
            } else {
                "request_blocked"
            },
            "Custom validation failed",
            MIDDLEWARE_HANDLER_NAME,
        );
        event.decorator_type = Some(String::from("content_filtering"));
        event.endpoint = Some(path.to_owned());
        event.method = Some(method.to_owned());
        event.metadata.insert(
            String::from("decorator_type"),
            serde_json::json!("content_filtering"),
        );
        event.metadata.insert(
            String::from("violation_type"),
            serde_json::json!("custom_validation"),
        );
        event
            .metadata
            .insert(String::from("validator_name"), serde_json::json!(validator));
        bus.send_event(&event);
    }
}

impl CustomChecksStageBuilder {
    /// Install the global `custom_request_check` function under `name`.
    #[must_use]
    pub fn custom_request(mut self, name: &str, check: CustomRequestFn) -> Self {
        self.custom_request = Some((name.to_owned(), check));
        self
    }

    /// Install the route `custom_validators` resolver.
    #[must_use]
    pub fn validators_resolver(mut self, resolver: RouteValidatorsResolver) -> Self {
        self.validators_resolver = Some(resolver);
        self
    }

    /// Set passive mode.
    #[must_use]
    pub const fn passive_mode(mut self, passive_mode: bool) -> Self {
        self.passive_mode = passive_mode;
        self
    }

    /// Install the middleware-event bus (the reference
    /// `custom_request_check` / `decorator_violation` emissions).
    #[must_use]
    pub fn events(mut self, bus: Arc<SecurityEventBus>) -> Self {
        self.events = Some(bus);
        self
    }

    /// Build the stage.
    #[must_use]
    pub fn build(self) -> CustomChecksStage {
        CustomChecksStage {
            custom_request: self.custom_request,
            validators_resolver: self.validators_resolver,
            passive_mode: self.passive_mode,
            events: self.events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage() -> CustomChecksStage {
        CustomChecksStage::builder()
            .custom_request(
                "maintenance_gate",
                Arc::new(|ctx| {
                    (ctx.path == "/admin").then_some(CustomResponse { status: Some(503) })
                }),
            )
            .validators_resolver(Arc::new(|path| {
                (path == "/private").then(|| {
                    vec![
                        (
                            String::from("post_only"),
                            Arc::new(|ctx: &CustomRequestContext<'_>| {
                                (ctx.method != "POST").then_some(ValidatorAnswer::Response(
                                    CustomResponse { status: Some(403) },
                                ))
                            }) as CustomValidatorFn,
                        ),
                        (
                            String::from("flagger"),
                            Arc::new(|_ctx: &CustomRequestContext<'_>| {
                                Some(ValidatorAnswer::TruthyNonResponse)
                            }) as CustomValidatorFn,
                        ),
                    ]
                })
            }))
            .build()
    }

    #[test]
    fn custom_request_blocks_with_the_function_response() {
        let stage = stage();
        let answer = stage
            .decide_custom_request("GET", "/admin", Some("192.0.2.9"))
            .expect("blocked");
        assert_eq!(answer.status, Some(503));
        assert_eq!(answer.function, "maintenance_gate");
        assert!(
            stage
                .decide_custom_request("GET", "/public", None)
                .is_none()
        );
    }

    #[test]
    fn no_custom_request_configured_never_blocks() {
        let stage = CustomChecksStage::builder().build();
        assert!(stage.decide_custom_request("GET", "/admin", None).is_none());
    }

    #[test]
    fn validators_run_in_order_and_a_response_blocks() {
        let stage = stage();
        let answer = stage
            .decide_custom_validators("/private", "GET", None)
            .expect("the GET violates the post_only gate");
        assert_eq!(answer.status, Some(403));
        assert_eq!(answer.validator, "post_only");

        // POST passes the first validator; the flagger's truthy
        // non-response logs but can never block.
        assert!(
            stage
                .decide_custom_validators("/private", "POST", None)
                .is_none()
        );
    }

    #[test]
    fn unconfigured_paths_pass() {
        let stage = stage();
        assert!(
            stage
                .decide_custom_validators("/public", "GET", None)
                .is_none()
        );
    }

    #[test]
    fn passive_mode_observes_without_blocking() {
        let stage = CustomChecksStage::builder()
            .custom_request(
                "gate",
                Arc::new(|_ctx| Some(CustomResponse { status: Some(503) })),
            )
            .validators_resolver(Arc::new(|_path| {
                Some(vec![(
                    String::from("blocker"),
                    Arc::new(|_ctx: &CustomRequestContext<'_>| {
                        Some(ValidatorAnswer::Response(CustomResponse {
                            status: Some(403),
                        }))
                    }) as CustomValidatorFn,
                )])
            }))
            .passive_mode(true)
            .build();
        assert!(stage.decide_custom_request("GET", "/admin", None).is_none());
        assert!(stage.decide_custom_validators("/x", "GET", None).is_none());
        assert!(stage.passive_mode());
    }

    #[test]
    fn anonymous_fallback_survives_the_reexport() {
        assert_eq!(anonymous_name(), "anonymous");
        assert_eq!(CUSTOM_REQUEST_CHECK_NAME, "custom_request");
        assert_eq!(CUSTOM_VALIDATORS_CHECK_NAME, "custom_validators");
    }

    fn recording_bus() -> (
        Arc<std::sync::Mutex<Vec<SecurityEvent>>>,
        Arc<SecurityEventBus>,
    ) {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let bus = Arc::new(SecurityEventBus::new(true).on_event(Arc::new(
            move |event: &SecurityEvent| {
                sink.lock().expect("sink").push(event.clone());
            },
        )));
        (log, bus)
    }

    #[test]
    fn the_custom_request_block_emits_the_reference_event() {
        let (log, bus) = recording_bus();
        let stage = CustomChecksStage::builder()
            .custom_request(
                "maintenance_gate",
                Arc::new(|_ctx| Some(CustomResponse { status: Some(503) })),
            )
            .events(bus)
            .build();
        stage
            .decide_custom_request("GET", "/admin", Some("192.0.2.9"))
            .expect("blocked");
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "custom_request_check");
        assert_eq!(events[0].action_taken, "request_blocked");
        assert_eq!(
            events[0].reason,
            "Custom request check returned blocking response"
        );
        assert_eq!(events[0].metadata["response_status"], 503);
        assert_eq!(events[0].metadata["check_function"], "maintenance_gate");
    }

    #[test]
    fn a_statusless_response_reads_unknown_and_passive_reads_logged_only() {
        let (log, bus) = recording_bus();
        let stage = CustomChecksStage::builder()
            .custom_request(
                "unnamed_shape",
                Arc::new(|_ctx| Some(CustomResponse { status: None })),
            )
            .passive_mode(true)
            .events(bus)
            .build();
        // Passive mode never blocks but still emits.
        assert!(stage.decide_custom_request("GET", "/x", None).is_none());
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action_taken, "logged_only");
        assert_eq!(events[0].metadata["response_status"], "unknown");
    }

    #[test]
    fn the_validator_failure_emits_the_decorator_violation() {
        let (log, bus) = recording_bus();
        let stage = CustomChecksStage::builder()
            .validators_resolver(Arc::new(|_path| {
                Some(vec![(
                    String::from("post_only"),
                    Arc::new(|_ctx: &CustomRequestContext<'_>| {
                        Some(ValidatorAnswer::Response(CustomResponse {
                            status: Some(403),
                        }))
                    }) as CustomValidatorFn,
                )])
            }))
            .events(bus)
            .build();
        stage
            .decide_custom_validators("/private", "GET", Some("192.0.2.9"))
            .expect("blocked");
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "decorator_violation");
        assert_eq!(
            events[0].decorator_type.as_deref(),
            Some("content_filtering")
        );
        assert_eq!(events[0].metadata["violation_type"], "custom_validation");
        assert_eq!(events[0].metadata["validator_name"], "post_only");
        assert_eq!(events[0].reason, "Custom validation failed");
    }

    #[test]
    fn the_truthy_non_response_emits_but_never_blocks() {
        let (log, bus) = recording_bus();
        let stage = CustomChecksStage::builder()
            .validators_resolver(Arc::new(|_path| {
                Some(vec![(
                    String::from("flagger"),
                    Arc::new(|_ctx: &CustomRequestContext<'_>| {
                        Some(ValidatorAnswer::TruthyNonResponse)
                    }) as CustomValidatorFn,
                )])
            }))
            .events(bus)
            .build();
        assert!(stage.decide_custom_validators("/x", "GET", None).is_none());
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1, "the reference emits on the truthy answer");
        assert_eq!(events[0].metadata["validator_name"], "flagger");
    }
}
