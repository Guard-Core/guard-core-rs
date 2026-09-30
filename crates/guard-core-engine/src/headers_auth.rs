//! The required-headers and authentication gate.
//!
//! This is the Rust family's port of two adjacent reference checks,
//! `guard_core/core/checks/implementations/required_headers.py` and
//! `guard_core/core/checks/implementations/authentication.py` (with the
//! credential extraction of `guard_core/core/checks/helpers.py::extract_credential`),
//! evaluated in the reference pipeline's order: required headers first, then
//! authentication. One call, [`decide`], carries a request's header values
//! through both:
//!
//! ```text
//! required headers, first failing rule in configured order:
//!   header absent or empty:          400 "Missing required header: {name}"
//!   value != expected (sentinel
//!   "required" = presence only):     400 "Header '{name}' does not match the required value"
//! authentication:
//!   authorization_header_required set: presence-only scheme check on
//!                                      the authorization header
//!   auth_required set: scheme check, then the auth verifier decides
//!   api_key_required set: the api key header must carry a value, then the
//!                         api key verifier decides
//!   any auth failure:                401 "Authentication required"
//! ```
//!
//! ## Details that mirror the reference exactly
//!
//! - A required header that is present but empty counts as missing
//!   (`if not actual` in the reference), expected values compare
//!   case-sensitively, and the `"required"` sentinel means presence-only.
//!   The block body is the reference's dynamic default message, which is
//!   why it is an owned [`String`] here.
//! - Credential extraction is `extract_credential`: the scheme names
//!   `"bearer"` and `"basic"` (exact, lowercase) require the exact `Bearer `
//!   / `Basic ` prefix and carry the remainder as the credential; any other
//!   scheme accepts the whole header value as the credential and fails only
//!   when it is empty.
//! - The presence check (`authorization_header_required`) short-circuits:
//!   when it is set, `auth_required`/`api_key_required` are not consulted,
//!   exactly as the reference check returns after it.
//! - Verifier resolution: the route's `auth_verifier` (or `api_key_verifier`
//!   on the API-key path) wins, the global `auth_verifier` is the fallback;
//!   a required credential with no verifier at all is a failure
//!   ("No auth verifier configured"), as in the reference. All failures
//!   answer the same body, `401 "Authentication required"` (the reasons are
//!   observability-only in the reference too).
//!
//! The header lookup is a closure (`name -> Option<&str>`, case-insensitive
//! on the name), so adapters feed it from `HeaderMap`, actix, or Rocket
//! types alike.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_engine::headers_auth::{
//!     decide, HeaderAuthRules, RequiredHeader, RouteVerifiers, REQUIRED_SENTINEL,
//! };
//!
//! let rules = HeaderAuthRules {
//!     required_headers: vec![RequiredHeader {
//!         name: "X-Request-ID".to_owned(),
//!         expected: REQUIRED_SENTINEL.to_owned(),
//!     }],
//!     auth_required: Some("bearer".to_owned()),
//!     ..HeaderAuthRules::default()
//! };
//! let verifiers = RouteVerifiers {
//!     auth: Some(Arc::new(|credential| credential == "token-1")),
//!     api_key: None,
//! };
//! let headers = [
//!     ("X-Request-ID", "abc"),
//!     ("Authorization", "Bearer token-1"),
//! ];
//! let lookup = |name: &str| {
//!     headers
//!         .iter()
//!         .find(|(key, _)| key.eq_ignore_ascii_case(name))
//!         .map(|(_, value)| (*value).to_owned())
//! };
//!
//! // Everything present: pass.
//! assert!(decide(&rules, &verifiers, lookup).is_none());
//!
//! // A missing required header is the reference's dynamic 400 body.
//! let block = decide(&rules, &verifiers, |_| None).expect("missing header");
//! assert_eq!(block.status, 400);
//! assert_eq!(block.body, "Missing required header: X-Request-ID");
//!
//! // A bad bearer credential is the fixed 401 shape.
//! let block = decide(
//!     &rules,
//!     &verifiers,
//!     |name| {
//!         if name.eq_ignore_ascii_case("Authorization") {
//!             Some("Bearer wrong".to_owned())
//!         } else {
//!             Some("abc".to_owned())
//!         }
//!     },
//! )
//! .expect("auth failure");
//! assert_eq!(block.status, 401);
//! assert_eq!(block.body, "Authentication required");
//! ```

use std::fmt;
use std::sync::Arc;

/// The required-header expected value meaning presence only
/// (`required_headers[name] == "required"` in the reference).
pub const REQUIRED_SENTINEL: &str = "required";

/// One required-header rule, in configured order: `name` must be present,
/// and its value must equal `expected` unless `expected` is
/// [`REQUIRED_SENTINEL`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredHeader {
    /// The header name (looked up case-insensitively).
    pub name: String,
    /// The exact required value, or [`REQUIRED_SENTINEL`].
    pub expected: String,
}

/// The route-level header and authentication rules.
///
/// The reference `RouteConfig` fields `required_headers`, `auth_required`,
/// `api_key_required`, `authorization_header_required`, and
/// `api_key_header`. The default has no rules: the gate passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderAuthRules {
    /// `required_headers`: checked in order, before authentication.
    pub required_headers: Vec<RequiredHeader>,
    /// `auth_required`: the authentication scheme
    /// (`"bearer"`, `"basic"`, or any other scheme name).
    pub auth_required: Option<String>,
    /// `api_key_required`: demand a non-empty `api_key_header` value.
    pub api_key_required: bool,
    /// `authorization_header_required`: a presence-only scheme check that
    /// short-circuits the other two authentication paths.
    pub authorization_header_required: Option<String>,
    /// `api_key_header`: the header the API key is read from.
    pub api_key_header: Option<String>,
}

impl HeaderAuthRules {
    /// Whether any rule is configured (the reference `applies_to`
    /// predicates).
    #[must_use]
    pub const fn has_rules(&self) -> bool {
        !self.required_headers.is_empty()
            || self.auth_required.is_some()
            || self.api_key_required
            || self.authorization_header_required.is_some()
    }
}

/// A credential verifier: `credential -> accepted?`.
///
/// The reference verifier is `verifier(request, credential) -> Principal |
/// None`; this port drops the request argument and the principal payload
/// (the stage discards both) and cannot observe the reference's
/// verifier-exception case.
pub type AuthVerifier = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The verifiers one route resolves to, after the caller merged the global
/// `auth_verifier` fallback (route verifier wins).
#[derive(Clone, Default)]
pub struct RouteVerifiers {
    /// The `auth_required` path's verifier.
    pub auth: Option<AuthVerifier>,
    /// The `api_key_required` path's verifier.
    pub api_key: Option<AuthVerifier>,
}

impl fmt::Debug for RouteVerifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteVerifiers")
            .field("auth", &self.auth.is_some())
            .field("api_key", &self.api_key.is_some())
            .finish()
    }
}

/// Which rule failed (the reference's `violation_type` values, carried for
/// observability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardViolation {
    /// `required_headers` entry absent or empty.
    MissingHeader,
    /// `required_headers` entry with a different value.
    MismatchedHeader,
    /// The `authorization_header_required` presence check failed
    /// (`violation_type="authorization_header"`).
    AuthorizationHeader,
    /// The `auth_required` / `api_key_required` path failed
    /// (`violation_type="require_auth"`).
    RequireAuth,
}

/// The block answer of a failed header or authentication rule: the status,
/// the reference default message body (dynamic for the required-header
/// shapes, which is why it is owned), and the violation type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardBlock {
    /// Which rule failed.
    pub violation: GuardViolation,
    /// `400` for the required-header shapes, `401` for every
    /// authentication failure.
    pub status: u16,
    /// The reference default message body.
    pub body: String,
}

impl fmt::Display for GuardBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status, self.body)
    }
}

/// The reference `extract_credential`: the credential of an
/// `authorization` header value under a scheme.
///
/// `"bearer"` requires the exact `Bearer ` prefix and `"basic"` the exact
/// `Basic ` prefix (each carrying the remainder as the credential); any
/// other scheme carries the whole header value and fails only when empty.
/// `None` means the reference returned a failure reason.
#[must_use]
pub fn extract_credential<'a>(auth_header: &'a str, auth_type: &str) -> Option<&'a str> {
    match auth_type {
        "bearer" => auth_header.strip_prefix("Bearer "),
        "basic" => auth_header.strip_prefix("Basic "),
        _ if auth_header.is_empty() => None,
        _ => Some(auth_header),
    }
}

/// Carry a request's header values through the required-headers check and
/// then the authentication check, in the reference pipeline's order.
///
/// `lookup` reads a header value case-insensitively by name (`None` when
/// absent). `Ok`-shaped for future-proofing is not needed: the checks are
/// total, so the return is a plain `Option` - `None` passes,
/// `Some(block)` is the reference's block answer.
#[must_use]
pub fn decide<L>(
    rules: &HeaderAuthRules,
    verifiers: &RouteVerifiers,
    lookup: L,
) -> Option<GuardBlock>
where
    L: Fn(&str) -> Option<String>,
{
    required_headers_block(rules, &lookup)
        .or_else(|| authentication_block(rules, verifiers, &lookup))
}

/// The required-headers sub-check: the first failing rule in order.
fn required_headers_block<L>(rules: &HeaderAuthRules, lookup: &L) -> Option<GuardBlock>
where
    L: Fn(&str) -> Option<String>,
{
    for rule in &rules.required_headers {
        let actual = lookup(&rule.name).filter(|value| !value.is_empty());
        let Some(actual) = actual else {
            return Some(GuardBlock {
                violation: GuardViolation::MissingHeader,
                status: 400,
                body: format!("Missing required header: {}", rule.name),
            });
        };
        if rule.expected != REQUIRED_SENTINEL && actual != rule.expected {
            return Some(GuardBlock {
                violation: GuardViolation::MismatchedHeader,
                status: 400,
                body: format!("Header '{}' does not match the required value", rule.name),
            });
        }
    }
    None
}

/// The authentication sub-check, in the reference's branch order.
fn authentication_block<L>(
    rules: &HeaderAuthRules,
    verifiers: &RouteVerifiers,
    lookup: &L,
) -> Option<GuardBlock>
where
    L: Fn(&str) -> Option<String>,
{
    // The presence check short-circuits everything else.
    if let Some(scheme) = rules.authorization_header_required.as_deref() {
        let auth_header = lookup("authorization").unwrap_or_default();
        return extract_credential(&auth_header, scheme).map_or_else(
            || {
                Some(GuardBlock {
                    violation: GuardViolation::AuthorizationHeader,
                    status: 401,
                    body: "Authentication required".to_owned(),
                })
            },
            |_| None,
        );
    }

    if let Some(scheme) = rules.auth_required.as_deref() {
        let auth_header = lookup("authorization").unwrap_or_default();
        let Some(credential) = extract_credential(&auth_header, scheme) else {
            return Some(auth_failure(GuardViolation::RequireAuth));
        };
        return resolve_verifier(verifiers.auth.as_ref(), credential);
    }

    if rules.api_key_required {
        let header = rules.api_key_header.as_deref().unwrap_or("");
        let credential = lookup(header).filter(|value| !value.is_empty());
        let Some(credential) = credential else {
            return Some(auth_failure(GuardViolation::RequireAuth));
        };
        return resolve_verifier(verifiers.api_key.as_ref(), &credential);
    }

    None
}

/// The reference's "No auth verifier configured" / "Authentication failed"
/// pair: both answer the fixed 401 shape.
fn resolve_verifier(verifier: Option<&AuthVerifier>, credential: &str) -> Option<GuardBlock> {
    let Some(verifier) = verifier else {
        return Some(auth_failure(GuardViolation::RequireAuth));
    };
    if verifier(credential) {
        None
    } else {
        Some(auth_failure(GuardViolation::RequireAuth))
    }
}

/// The reference `create_error_response(status_code=401,
/// default_message="Authentication required")` shape every auth failure
/// answers with.
fn auth_failure(violation: GuardViolation) -> GuardBlock {
    GuardBlock {
        violation,
        status: 401,
        body: "Authentication required".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over case-insensitive name/value pairs, in the owned shape
    /// `decide` reads.
    fn lookup_of<'h>(headers: &'h [(&'h str, &'h str)]) -> impl Fn(&str) -> Option<String> + 'h {
        move |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| (*value).to_owned())
        }
    }

    fn bearer_rules(scheme: &str) -> HeaderAuthRules {
        HeaderAuthRules {
            auth_required: Some(scheme.to_owned()),
            ..HeaderAuthRules::default()
        }
    }

    #[test]
    fn empty_rules_pass_everything() {
        let rules = HeaderAuthRules::default();
        assert!(!rules.has_rules());
        assert!(decide(&rules, &RouteVerifiers::default(), |_| None).is_none());
    }

    #[test]
    fn has_rules_tracks_each_field() {
        let rules = HeaderAuthRules {
            api_key_required: true,
            ..HeaderAuthRules::default()
        };
        assert!(rules.has_rules());
        let rules = HeaderAuthRules {
            authorization_header_required: Some("bearer".to_owned()),
            ..HeaderAuthRules::default()
        };
        assert!(rules.has_rules());
    }

    #[test]
    fn required_header_missing_or_empty_is_a_dynamic_400() {
        let rules = HeaderAuthRules {
            required_headers: vec![RequiredHeader {
                name: "X-Request-ID".to_owned(),
                expected: REQUIRED_SENTINEL.to_owned(),
            }],
            ..HeaderAuthRules::default()
        };
        let block = decide(&rules, &RouteVerifiers::default(), |_| None).expect("missing");
        assert_eq!(block.violation, GuardViolation::MissingHeader);
        assert_eq!(block.status, 400);
        assert_eq!(block.body, "Missing required header: X-Request-ID");
        assert_eq!(
            block.to_string(),
            "400 Missing required header: X-Request-ID"
        );

        // Present but empty counts as missing (`if not actual`).
        let block = decide(
            &rules,
            &RouteVerifiers::default(),
            lookup_of(&[("X-Request-ID", "")]),
        )
        .expect("empty");
        assert_eq!(block.violation, GuardViolation::MissingHeader);
    }

    #[test]
    fn required_header_lookup_is_case_insensitive_and_values_exact() {
        let rules = HeaderAuthRules {
            required_headers: vec![RequiredHeader {
                name: "X-Role".to_owned(),
                expected: "admin".to_owned(),
            }],
            ..HeaderAuthRules::default()
        };
        assert!(
            decide(
                &rules,
                &RouteVerifiers::default(),
                lookup_of(&[("x-role", "admin")])
            )
            .is_none()
        );
        // The value comparison is case-sensitive.
        let block = decide(
            &rules,
            &RouteVerifiers::default(),
            lookup_of(&[("X-ROLE", "Admin")]),
        )
        .expect("mismatch");
        assert_eq!(block.violation, GuardViolation::MismatchedHeader);
        assert_eq!(block.status, 400);
        assert_eq!(
            block.body,
            "Header 'X-Role' does not match the required value"
        );
    }

    #[test]
    fn required_headers_report_the_first_failing_rule_in_order() {
        let rules = HeaderAuthRules {
            required_headers: vec![
                RequiredHeader {
                    name: "A".to_owned(),
                    expected: REQUIRED_SENTINEL.to_owned(),
                },
                RequiredHeader {
                    name: "B".to_owned(),
                    expected: "yes".to_owned(),
                },
                RequiredHeader {
                    name: "C".to_owned(),
                    expected: REQUIRED_SENTINEL.to_owned(),
                },
            ],
            ..HeaderAuthRules::default()
        };
        let lookup = lookup_of(&[("A", "1"), ("B", "no"), ("C", "")]);
        let block = decide(&rules, &RouteVerifiers::default(), lookup).expect("B fails");
        assert_eq!(block.body, "Header 'B' does not match the required value");

        let lookup = lookup_of(&[("A", "1"), ("B", "yes")]);
        let block = decide(&rules, &RouteVerifiers::default(), lookup).expect("C fails");
        assert_eq!(block.body, "Missing required header: C");
    }

    #[test]
    fn bearer_scheme_demands_the_exact_prefix() {
        let verifiers = RouteVerifiers::default();
        // No verifier configured: a valid credential still fails with the
        // "No auth verifier configured" shape (the fixed 401 body).
        assert!(
            decide(
                &bearer_rules("bearer"),
                &verifiers,
                lookup_of(&[("authorization", "Bearer tok")])
            )
            .is_some()
        );

        let rules = bearer_rules("bearer");
        let verifiers = RouteVerifiers {
            auth: Some(Arc::new(|_| true)),
            api_key: None,
        };
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Bearer tok")])
            )
            .is_none()
        );
        // Case of the scheme prefix matters; the scheme name has no case
        // variants ("bearer" is matched exactly).
        for junk in ["bearer tok", "Bearer", "Basic tok", "tok"] {
            assert!(
                decide(&rules, &verifiers, lookup_of(&[("authorization", junk)])).is_some(),
                "'{junk}' must fail the bearer presence check"
            );
        }
        // The prefix alone still carries an (empty) credential and passes,
        // like Python's `auth_header[len("Bearer "):]` returning "".
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Bearer ")])
            )
            .is_none()
        );
        // A missing authorization header fails too.
        assert!(decide(&rules, &verifiers, |_| None).is_some());
    }

    #[test]
    fn basic_scheme_demands_the_exact_prefix() {
        let rules = bearer_rules("basic");
        let verifiers = RouteVerifiers {
            auth: Some(Arc::new(|_| true)),
            api_key: None,
        };
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Basic dXNlcjpwdw==")])
            )
            .is_none()
        );
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Bearer dXNlcjpwdw==")])
            )
            .is_some()
        );
    }

    #[test]
    fn other_schemes_carry_the_whole_header_value() {
        let rules = bearer_rules("apikey");
        let verifiers = RouteVerifiers {
            auth: Some(Arc::new(|credential| credential == "raw-key")),
            api_key: None,
        };
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "raw-key")])
            )
            .is_none()
        );
        // The whole value, prefix included, is the credential.
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Bearer raw-key")])
            )
            .is_some()
        );
        // Empty is the only failure of the presence half.
        assert!(decide(&rules, &verifiers, lookup_of(&[("authorization", "")])).is_some());
    }

    #[test]
    fn verifier_outcomes_are_the_fixed_401_shape() {
        let rules = bearer_rules("bearer");
        let accept = RouteVerifiers {
            auth: Some(Arc::new(|_| true)),
            api_key: None,
        };
        let reject = RouteVerifiers {
            auth: Some(Arc::new(|_| false)),
            api_key: None,
        };
        assert!(decide(&rules, &accept, lookup_of(&[("authorization", "Bearer t")])).is_none());
        let block =
            decide(&rules, &reject, lookup_of(&[("authorization", "Bearer t")])).expect("rejected");
        assert_eq!(block.violation, GuardViolation::RequireAuth);
        assert_eq!(block.status, 401);
        assert_eq!(block.body, "Authentication required");

        // No verifier at all is the reference's "No auth verifier
        // configured" failure, same body.
        let block = decide(
            &rules,
            &RouteVerifiers::default(),
            lookup_of(&[("authorization", "Bearer t")]),
        )
        .expect("no verifier");
        assert_eq!(block.status, 401);
        assert_eq!(block.body, "Authentication required");
    }

    #[test]
    fn presence_scheme_short_circuits_the_other_auth_paths() {
        let rules = HeaderAuthRules {
            auth_required: Some("bearer".to_owned()),
            api_key_required: true,
            api_key_header: Some("X-Key".to_owned()),
            authorization_header_required: Some("basic".to_owned()),
            ..HeaderAuthRules::default()
        };
        // A valid Basic header passes even though auth_required and
        // api_key_required would both fail: the presence check returned.
        let verifiers = RouteVerifiers::default();
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Basic ok")])
            )
            .is_none()
        );
        // The prefix alone carries an empty credential and passes as well.
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Basic ")])
            )
            .is_none()
        );
        // A wrong prefix fails with the presence violation.
        let block = decide(
            &rules,
            &verifiers,
            lookup_of(&[("authorization", "bearer x")]),
        )
        .expect("presence");
        assert_eq!(block.violation, GuardViolation::AuthorizationHeader);
    }

    #[test]
    fn api_key_path_reads_its_header_and_verifier() {
        let rules = HeaderAuthRules {
            api_key_required: true,
            api_key_header: Some("X-Key".to_owned()),
            ..HeaderAuthRules::default()
        };
        let verifiers = RouteVerifiers {
            auth: None,
            api_key: Some(Arc::new(|credential| credential == "k-1")),
        };
        assert!(decide(&rules, &verifiers, lookup_of(&[("X-Key", "k-1")])).is_none());
        // Missing, empty, or rejected all fail with the 401 shape.
        for headers in [
            vec![],
            vec![("X-Key", "")],
            vec![("X-Key", "wrong")],
            vec![("X-Other", "k-1")],
        ] {
            let block = decide(&rules, &verifiers, lookup_of(&headers)).expect("api key failure");
            assert_eq!(block.violation, GuardViolation::RequireAuth);
            assert_eq!(block.status, 401);
        }
        // No configured header name reads nothing ("api_key_header or \"\"").
        let rules = HeaderAuthRules {
            api_key_required: true,
            ..HeaderAuthRules::default()
        };
        let verifiers = RouteVerifiers {
            api_key: Some(Arc::new(|_| true)),
            auth: None,
        };
        assert!(decide(&rules, &verifiers, lookup_of(&[("X-Key", "k-1")])).is_some());
    }

    #[test]
    fn required_headers_run_before_authentication() {
        let rules = HeaderAuthRules {
            required_headers: vec![RequiredHeader {
                name: "X-Request-ID".to_owned(),
                expected: REQUIRED_SENTINEL.to_owned(),
            }],
            auth_required: Some("bearer".to_owned()),
            ..HeaderAuthRules::default()
        };
        let verifiers = RouteVerifiers::default();
        // Both would fail: the missing header answers first, with the 400.
        let block = decide(&rules, &verifiers, |_| None).expect("header first");
        assert_eq!(block.status, 400);
        assert_eq!(block.body, "Missing required header: X-Request-ID");
    }

    #[test]
    fn auth_required_beats_api_key_when_both_set() {
        let rules = HeaderAuthRules {
            auth_required: Some("bearer".to_owned()),
            api_key_required: true,
            api_key_header: Some("X-Key".to_owned()),
            ..HeaderAuthRules::default()
        };
        let verifiers = RouteVerifiers {
            auth: Some(Arc::new(|_| true)),
            api_key: Some(Arc::new(|_| false)),
        };
        // Only the bearer credential present: the auth path passes and the
        // api key path is never reached (the reference returns after
        // _resolve_credential).
        assert!(
            decide(
                &rules,
                &verifiers,
                lookup_of(&[("authorization", "Bearer t")])
            )
            .is_none()
        );
    }

    #[test]
    fn route_verifiers_debug_renders_the_verifier_presence() {
        let verifiers = RouteVerifiers {
            auth: None,
            api_key: None,
        };
        assert!(format!("{verifiers:?}").contains("RouteVerifiers"));
    }
}
