//! The custom function seams: the reference pipeline's ninth and
//! seventeenth checks.
//!
//! This is the Rust family's port of the two checks the reference pipeline
//! runs host-supplied functions through:
//!
//! - `guard_core/core/checks/implementations/custom_validators.py`: a
//!   route's `custom_validators` list, run in order, first truthy response
//!   wins.
//! - `guard_core/core/checks/implementations/custom_request.py`: the
//!   global `custom_request_check` function.
//!
//! The reference seams are async callables over the request; the Rust
//! family's are sync boxed functions over a [`CustomRequestContext`] (the
//! request facts the reference's checks can see). Both checks share the
//! same shapes:
//!
//! ```text
//! custom_validators (route-scoped, in order, first truthy wins):
//!   validator returns None:            continue
//!   validator returns a response:      Failed (block with the validator's
//!                                      own response, the reference returns
//!                                      it as-is, never create_error_response)
//!   validator returns a truthy
//!   non-response:                      Failed with no block (the reference
//!                                      logs and emits but does not block)
//! custom_request (global):
//!   check returns None:                Allowed
//!   check returns a response:          Blocked with it (the reference
//!                                      applies the response modifier;
//!                                      passive mode logs only)
//! ```
//!
//! Names are explicit on the seam (the reference reads `__name__`,
//! falling back to `"anonymous"` for unnamed callables): a Rust closure
//! carries no name, so hosts name them at registration.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_engine::custom_checks::{
//!     decide_custom_request, CustomRequestContext, CustomRequestFn, CustomRequestVerdict,
//!     CustomResponse,
//! };
//!
//! let check: CustomRequestFn = Arc::new(|_ctx: &CustomRequestContext<'_>| {
//!     Some(CustomResponse { status: Some(418) })
//! });
//! let ctx = CustomRequestContext { method: "GET", path: "/", client_ip: None };
//! let verdict = decide_custom_request(&check, "block_maintenance", &ctx);
//! assert_eq!(
//!     verdict,
//!     CustomRequestVerdict::Blocked { status: Some(418), function: "block_maintenance".to_owned() }
//! );
//! ```

use std::sync::Arc;

/// The `custom_request` check's stable name (`check_name`).
pub const CUSTOM_REQUEST_CHECK_NAME: &str = "custom_request";

/// The `custom_validators` check's stable name (`check_name`).
pub const CUSTOM_VALIDATORS_CHECK_NAME: &str = "custom_validators";

/// The request facts a custom function sees (the pieces of `GuardRequest`
/// the reference's checks read; everything else stays with the host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomRequestContext<'a> {
    /// The request method.
    pub method: &'a str,
    /// The request URL path.
    pub path: &'a str,
    /// The client IP, when resolved.
    pub client_ip: Option<&'a str>,
}

/// A response a custom function hands back. `status` is the response's
/// status code when it carries one (the reference's
/// `response_status ... else "unknown"` metadata arm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomResponse {
    /// The response's status code, `None` for a response without one.
    pub status: Option<u16>,
}

/// The host-supplied `custom_request_check` function.
pub type CustomRequestFn =
    Arc<dyn Fn(&CustomRequestContext<'_>) -> Option<CustomResponse> + Send + Sync>;

/// What a route validator returned: the reference's truthy response
/// (blocks with its own shape) versus a truthy non-response value (logs
/// and emits, never blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorAnswer {
    /// A truthy non-`GuardResponse` value: observability only.
    TruthyNonResponse,
    /// A real response: blocks with it as-is.
    Response(CustomResponse),
}

/// The host-supplied route validator function.
pub type CustomValidatorFn =
    Arc<dyn Fn(&CustomRequestContext<'_>) -> Option<ValidatorAnswer> + Send + Sync>;

/// What [`decide_custom_request`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomRequestVerdict {
    /// The check returned nothing: allow.
    Allowed,
    /// The check returned a response: the reference emits
    /// `custom_request_check` with the response status (or `"unknown"`)
    /// and the function name (or `"anonymous"`), then applies the
    /// response modifier and returns it.
    Blocked {
        /// The response's status, `None` for the `"unknown"` arm.
        status: Option<u16>,
        /// The registered function name, `"anonymous"` when unnamed.
        function: String,
    },
}

/// The `custom_request` check body: the function runs once; a returned
/// response blocks with it.
#[must_use]
pub fn decide_custom_request(
    check: &CustomRequestFn,
    function_name: &str,
    ctx: &CustomRequestContext<'_>,
) -> CustomRequestVerdict {
    if let Some(response) = check(ctx) {
        return CustomRequestVerdict::Blocked {
            status: response.status,
            function: function_name.to_owned(),
        };
    }
    CustomRequestVerdict::Allowed
}

/// What [`decide_custom_validators`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomValidatorsVerdict {
    /// Every validator passed (or the route carries none).
    Allowed,
    /// A validator returned a truthy answer: the reference logs and emits
    /// (`"Custom validation failed"`, `decorator_type="content_filtering"`,
    /// `violation_type="custom_validation"`, the validator's name or
    /// `"anonymous"`); `block` carries the response only when the answer
    /// was a real response - a truthy non-response never blocks.
    Failed {
        /// The blocking response, when the answer was one.
        block: Option<CustomResponse>,
        /// The validator's registered name, `"anonymous"` when unnamed.
        validator: String,
    },
}

/// The `custom_validators` check body: run in order, first truthy answer
/// wins (the reference stops at the first truthy response, never running
/// the rest).
#[must_use]
pub fn decide_custom_validators(
    validators: &[(String, CustomValidatorFn)],
    ctx: &CustomRequestContext<'_>,
) -> CustomValidatorsVerdict {
    for (name, validator) in validators {
        let Some(answer) = validator(ctx) else {
            continue;
        };
        return CustomValidatorsVerdict::Failed {
            block: match answer {
                ValidatorAnswer::Response(response) => Some(response),
                ValidatorAnswer::TruthyNonResponse => None,
            },
            validator: name.clone(),
        };
    }
    CustomValidatorsVerdict::Allowed
}

/// The `"anonymous"` name the reference falls back to for unnamed
/// callables.
#[must_use]
pub fn anonymous_name() -> String {
    String::from("anonymous")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>() -> CustomRequestContext<'a> {
        CustomRequestContext {
            method: "GET",
            path: "/private",
            client_ip: Some("192.0.2.9"),
        }
    }

    #[test]
    fn custom_request_passes_and_blocks() {
        let ctx = ctx();
        let pass: CustomRequestFn = Arc::new(|_ctx| None);
        assert_eq!(
            decide_custom_request(&pass, "my_check", &ctx),
            CustomRequestVerdict::Allowed
        );

        let block: CustomRequestFn = Arc::new(|_ctx| Some(CustomResponse { status: Some(403) }));
        assert_eq!(
            decide_custom_request(&block, "my_check", &ctx),
            CustomRequestVerdict::Blocked {
                status: Some(403),
                function: "my_check".to_owned()
            }
        );

        // A response without a status is the reference's "unknown" arm.
        let unknown: CustomRequestFn = Arc::new(|_ctx| Some(CustomResponse { status: None }));
        assert_eq!(
            decide_custom_request(&unknown, "my_check", &ctx),
            CustomRequestVerdict::Blocked {
                status: None,
                function: "my_check".to_owned()
            }
        );
    }

    #[test]
    fn validators_run_in_order_and_first_truthy_wins() {
        let ctx = ctx();
        let never: CustomValidatorFn = Arc::new(|_ctx| None);
        let blocking: CustomValidatorFn = Arc::new(|_ctx| {
            Some(ValidatorAnswer::Response(CustomResponse {
                status: Some(403),
            }))
        });
        let flagging: CustomValidatorFn = Arc::new(|_ctx| Some(ValidatorAnswer::TruthyNonResponse));

        // All pass.
        let all_pass = vec![
            (String::from("first"), never.clone()),
            (String::from("second"), never.clone()),
        ];
        assert_eq!(
            decide_custom_validators(&all_pass, &ctx),
            CustomValidatorsVerdict::Allowed
        );

        // First truthy wins: the earlier validator's name rides the verdict.
        let first_blocks = vec![
            (String::from("first"), never.clone()),
            (String::from("second"), blocking.clone()),
            (String::from("third"), flagging.clone()),
        ];
        assert_eq!(
            decide_custom_validators(&first_blocks, &ctx),
            CustomValidatorsVerdict::Failed {
                block: Some(CustomResponse { status: Some(403) }),
                validator: "second".to_owned()
            }
        );

        // The first truthy answer wins even when it cannot block: the
        // flagging validator's name rides a blockless verdict.
        let first_flags = vec![
            (String::from("first"), flagging.clone()),
            (String::from("second"), blocking.clone()),
        ];
        assert_eq!(
            decide_custom_validators(&first_flags, &ctx),
            CustomValidatorsVerdict::Failed {
                block: None,
                validator: "first".to_owned()
            }
        );
    }

    #[test]
    fn a_truthy_non_response_logs_but_never_blocks() {
        let ctx = ctx();
        let flagging: CustomValidatorFn = Arc::new(|_ctx| Some(ValidatorAnswer::TruthyNonResponse));
        let validators = vec![(String::from("flagger"), flagging)];
        assert_eq!(
            decide_custom_validators(&validators, &ctx),
            CustomValidatorsVerdict::Failed {
                block: None,
                validator: "flagger".to_owned()
            },
            "the reference returns the validator's response only when it is a \
             real GuardResponse; a truthy non-response cannot block"
        );
    }

    #[test]
    fn the_context_carries_the_request_facts() {
        let seen: CustomValidatorFn = Arc::new(|ctx| {
            // The validator can decide on the method/path/client_ip.
            (ctx.path == "/private" && ctx.method == "POST").then_some(ValidatorAnswer::Response(
                CustomResponse { status: Some(403) },
            ))
        });
        let validators = vec![(String::from("gate"), seen)];
        assert_eq!(
            decide_custom_validators(&validators, &ctx()),
            CustomValidatorsVerdict::Allowed,
            "GET /private passes the POST-only gate"
        );
        let post = CustomRequestContext {
            method: "POST",
            path: "/private",
            client_ip: None,
        };
        assert_eq!(
            decide_custom_validators(&validators, &post),
            CustomValidatorsVerdict::Failed {
                block: Some(CustomResponse { status: Some(403) }),
                validator: "gate".to_owned()
            },
            "a real GuardResponse both blocks and carries the response"
        );
    }

    #[test]
    fn anonymous_fallback_name() {
        assert_eq!(anonymous_name(), "anonymous");
    }
}
