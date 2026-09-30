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
                // the validator's response only in active mode).
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

    /// Build the stage.
    #[must_use]
    pub fn build(self) -> CustomChecksStage {
        CustomChecksStage {
            custom_request: self.custom_request,
            validators_resolver: self.validators_resolver,
            passive_mode: self.passive_mode,
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

    #[test]
    fn the_stage_renders_debug_and_unconfigured_seams_pass() {
        let built = stage();
        assert!(format!("{built:?}").starts_with("CustomChecksStage"));

        // No validators resolver at all: the route check passes.
        let bare = CustomChecksStage::builder().build();
        assert!(
            bare.decide_custom_validators("/private", "GET", None)
                .is_none()
        );

        // A resolver that answers with an empty validator list: the check
        // runs and allows.
        let empty = CustomChecksStage::builder()
            .validators_resolver(Arc::new(|_path| Some(Vec::new())))
            .build();
        assert!(
            empty
                .decide_custom_validators("/private", "GET", None)
                .is_none(),
            "no validators: the check allows"
        );
    }
}
