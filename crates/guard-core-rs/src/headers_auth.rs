//! The required-headers and authentication pipeline stage for tower stacks.
//!
//! One `tower::Layer` that answers the reference engine's
//! `required_headers` check
//! (`guard_core/core/checks/implementations/required_headers.py`) and
//! `authentication` check
//! (`guard_core/core/checks/implementations/authentication.py`) in the
//! pipeline's order, over the decision core
//! [`guard_core_engine::headers_auth`]:
//!
//! ```text
//! route resolves to no rules (or no resolver):   pass through
//! first failing required-header rule:            400 "Missing required header: {name}"
//!                                                400 "Header '{n}' does not match the required value"
//! any authentication failure:                    401 "Authentication required"
//! everything else:                               pass through
//! ```
//!
//! ## Reference contract, point by point
//!
//! - **Route-scoped rules, global verifier fallback**: the rules live on
//!   the reference `RouteConfig`; the stage learns them through the
//!   [`RouteGuards`] resolver (`path -> Option<RouteGuard>`, the tower
//!   counterpart of `request.state.route_config`). The global
//!   `config.auth_verifier` is the stage-level fallback each route's
//!   `auth_verifier` / `api_key_verifier` overrides.
//! - **Order**: required headers run before authentication, and the stage
//!   sits where the reference pipeline runs them: after the
//!   request-size/content stage, before the IP-visible stages.
//! - **Bodies**: the required-header blocks answer the reference's dynamic
//!   default messages; every authentication failure answers the fixed
//!   `401 "Authentication required"` (the reasons are observability-only
//!   in the reference too; the [`GuardViolation`] on each block carries
//!   the reference `violation_type`).
//! - **Not mirrored**: the reference logs via `log_activity`, emits
//!   `EVENT_DECORATOR_VIOLATION` events, honors `passive_mode`, consults
//!   `custom_error_responses` for body overrides, and on success stores
//!   `request.state.auth_principal` (the verifier returns a principal;
//!   this port's verifier is a predicate and the stage discards the
//!   outcome). None of those config surfaces exist in the Rust family yet.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_engine::headers_auth::{
//!     HeaderAuthRules, RequiredHeader, REQUIRED_SENTINEL,
//! };
//! use guard_core_rs::headers_auth::{HeadersAuthStage, RouteGuard};
//!
//! let stage = HeadersAuthStage::new(
//!     None,
//!     Arc::new(|path| {
//!         (path == "/admin").then(|| Arc::new(RouteGuard {
//!             rules: HeaderAuthRules {
//!                 required_headers: vec![RequiredHeader {
//!                     name: "X-Request-ID".to_owned(),
//!                     expected: REQUIRED_SENTINEL.to_owned(),
//!                 }],
//!                 authorization_header_required: Some("bearer".to_owned()),
//!                 ..HeaderAuthRules::default()
//!             },
//!             verifier: None,
//!             api_key_verifier: None,
//!         }))
//!     }),
//! );
//!
//! let passing = stage
//!     .decide("/admin", &[("x-request-id", "abc"), ("authorization", "Bearer tok")])
//!     .map(|(_, block)| block);
//! assert!(passing.is_none());
//!
//! let (_, block) = stage
//!     .decide("/admin", &[("authorization", "Bearer tok")])
//!     .expect("missing header");
//! assert_eq!(block.status, 400);
//! assert_eq!(block.body, "Missing required header: X-Request-ID");
//!
//! let (_, block) = stage
//!     .decide("/admin", &[("x-request-id", "abc")])
//!     .expect("auth failure");
//! assert_eq!(block.status, 401);
//! assert_eq!(block.body, "Authentication required");
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Request, Response, StatusCode};

pub use guard_core_engine::headers_auth::{
    AuthVerifier, GuardBlock, GuardViolation, HeaderAuthRules, REQUIRED_SENTINEL, RequiredHeader,
    RouteVerifiers, decide as decide_guard, extract_credential,
};

/// The fixed answer body of every authentication failure
/// (`AuthenticationCheck`'s default message).
pub const AUTHENTICATION_REQUIRED_BODY: &str = "Authentication required";

/// One route's rules plus its verifier overrides: the reference
/// `RouteConfig.auth_verifier` / `RouteConfig.api_key_verifier` pair, which
/// override the stage-level `auth_verifier` fallback.
#[derive(Clone, Default)]
pub struct RouteGuard {
    /// The route's header and authentication rules.
    pub rules: HeaderAuthRules,
    /// `RouteConfig.auth_verifier` (the `auth_required` path).
    pub verifier: Option<AuthVerifier>,
    /// `RouteConfig.api_key_verifier` (the `api_key_required` path).
    pub api_key_verifier: Option<AuthVerifier>,
}

/// How the stage learns a path's guard rules.
///
/// The reference reads them from `request.state.route_config`; a tower
/// stack resolves them from the request path. `None` (no entry) means the
/// route carries no rules and passes, the reference's no-decorator shape.
pub type RouteGuards = Arc<dyn Fn(&str) -> Option<Arc<RouteGuard>> + Send + Sync>;

/// The stage's answer: status plus the (dynamic) reference default message
/// body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageAnswer {
    /// `400` for the required-header shapes, `401` for authentication.
    pub status: StatusCode,
    /// The reference default message body.
    pub body: String,
}

/// The required-headers and authentication stage over one route resolver.
///
/// Build it once at startup with [`HeadersAuthStage::new`] and install it
/// with [`HeadersAuthStageLayer`]. The stage is cheaply clonable; the
/// resolver and the global verifier are shared.
#[derive(Clone)]
pub struct HeadersAuthStage {
    global_verifier: Option<AuthVerifier>,
    routes: RouteGuards,
}

impl fmt::Debug for HeadersAuthStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadersAuthStage")
            .field("global_verifier", &self.global_verifier.is_some())
            .finish_non_exhaustive()
    }
}

impl HeadersAuthStage {
    /// Build the stage over `routes` with the global `auth_verifier`
    /// fallback (`SecurityConfig.auth_verifier`; `None` when unset).
    #[must_use]
    pub fn new(global_verifier: Option<AuthVerifier>, routes: RouteGuards) -> Self {
        Self {
            global_verifier,
            routes,
        }
    }

    /// One pass of the stage: `path` selects the route guard and `headers`
    /// carries the request headers (looked up case-insensitively). `None`
    /// passes; `Some` carries the status, the reference default message
    /// body, and the violation type.
    #[must_use]
    pub fn decide(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Option<(GuardViolation, StageAnswer)> {
        let guard = (self.routes)(path)?;
        let verifiers = RouteVerifiers {
            auth: guard
                .verifier
                .clone()
                .or_else(|| self.global_verifier.clone()),
            api_key: guard
                .api_key_verifier
                .clone()
                .or_else(|| self.global_verifier.clone()),
        };
        let lookup = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| (*value).to_owned())
        };
        decide_guard(&guard.rules, &verifiers, lookup).map(|block| {
            (
                block.violation,
                StageAnswer {
                    status: StatusCode::from_u16(block.status).expect("reference statuses"),
                    body: block.body,
                },
            )
        })
    }
}

/// The `tower::Layer` carrying [`HeadersAuthStage`].
///
/// Wrap any `Service<http::Request<B>>` whose responses are
/// `http::Response<ResBody>` with `ResBody: From<String>` (Axum's body and
/// `http_body_util::Full<Bytes>` qualify) and the stage answers the
/// reference's block shapes itself.
#[derive(Clone)]
pub struct HeadersAuthStageLayer {
    stage: HeadersAuthStage,
}

impl HeadersAuthStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: HeadersAuthStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for HeadersAuthStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadersAuthStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for HeadersAuthStageLayer {
    type Service = HeadersAuthStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeadersAuthStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct HeadersAuthStageService<S> {
    inner: S,
    stage: HeadersAuthStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for HeadersAuthStageService<S>
where
    S: ::tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: From<String> + From<&'static str> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let path = request.uri().path().to_owned();
        let map = request.headers().clone();
        let pairs: Vec<(String, String)> = map
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        if let Some((_, answer)) = self.stage.decide(&path, &borrowed) {
            let response = render(answer);
            return Box::pin(async move { Ok(response) });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

/// Render the stage's answer into the wrapped service's response body type.
fn render<ResBody: From<String>>(answer: StageAnswer) -> Response<ResBody> {
    let mut response = Response::new(ResBody::from(answer.body));
    *response.status_mut() = answer.status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ::tower::{Service, ServiceBuilder};

    const HEADER_ONLY: HeaderAuthRules = HeaderAuthRules {
        required_headers: Vec::new(),
        auth_required: None,
        api_key_required: false,
        authorization_header_required: None,
        api_key_header: None,
    };

    fn admin_guard(verifier: Option<AuthVerifier>) -> RouteGuards {
        Arc::new(move |path: &str| {
            (path == "/admin").then(|| {
                Arc::new(RouteGuard {
                    rules: HeaderAuthRules {
                        required_headers: vec![RequiredHeader {
                            name: "X-Request-ID".to_owned(),
                            expected: REQUIRED_SENTINEL.to_owned(),
                        }],
                        auth_required: Some("bearer".to_owned()),
                        ..HEADER_ONLY
                    },
                    verifier: verifier.clone(),
                    api_key_verifier: None,
                })
            })
        })
    }

    fn presence_guard() -> RouteGuards {
        Arc::new(|path: &str| {
            (path == "/admin").then(|| {
                Arc::new(RouteGuard {
                    rules: HeaderAuthRules {
                        required_headers: vec![RequiredHeader {
                            name: "X-Request-ID".to_owned(),
                            expected: REQUIRED_SENTINEL.to_owned(),
                        }],
                        authorization_header_required: Some("bearer".to_owned()),
                        ..HEADER_ONLY
                    },
                    verifier: None,
                    api_key_verifier: None,
                })
            })
        })
    }

    fn stage_with(routes: RouteGuards) -> HeadersAuthStage {
        HeadersAuthStage::new(None, routes)
    }

    #[test]
    fn unconfigured_paths_pass_everything() {
        let stage = stage_with(admin_guard(None));
        assert!(stage.decide("/public", &[]).is_none());
        assert!(
            stage
                .decide("/public", &[("authorization", "junk")])
                .is_none()
        );
    }

    #[test]
    fn required_header_blocks_use_the_dynamic_reference_bodies() {
        let stage = stage_with(admin_guard(None));

        let (violation, answer) = stage.decide("/admin", &[]).expect("missing header");
        assert_eq!(violation, GuardViolation::MissingHeader);
        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        assert_eq!(answer.body, "Missing required header: X-Request-ID");

        let (violation, answer) = stage
            .decide(
                "/admin",
                &[("x-request-id", ""), ("authorization", "Bearer t")],
            )
            .expect("empty header");
        assert_eq!(violation, GuardViolation::MissingHeader);
        assert_eq!(answer.body, "Missing required header: X-Request-ID");

        let (violation, answer) = stage
            .decide(
                "/admin",
                &[("X-Request-ID", "abc"), ("authorization", "junk")],
            )
            .expect("auth failure");
        assert_eq!(violation, GuardViolation::RequireAuth);
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.body, AUTHENTICATION_REQUIRED_BODY);
    }

    #[test]
    fn presence_scheme_short_circuits_the_verifier_paths() {
        // A route guard with only a bearer presence rule and no verifier
        // passes a well-formed header without consulting any verifier...
        let stage = stage_with(presence_guard());
        assert!(
            stage
                .decide(
                    "/admin",
                    &[
                        ("x-request-id", "abc"),
                        ("authorization", "Bearer anything")
                    ]
                )
                .is_none()
        );
        // ...while a malformed one fails with the presence violation.
        let (violation, answer) = stage
            .decide(
                "/admin",
                &[("x-request-id", "abc"), ("authorization", "junk")],
            )
            .expect("presence failure");
        assert_eq!(violation, GuardViolation::AuthorizationHeader);
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        let _ = stage_with(admin_guard(None));
    }

    #[test]
    fn a_route_verifier_overrides_the_global_fallback() {
        // Route verifier accepts only "good"; the global fallback accepts
        // everything. A "good" credential passes, proving the route
        // verifier won (the global one accepts either way, so also check
        // the rejection side below).
        let stage = HeadersAuthStage::new(
            Some(Arc::new(|_| true)),
            admin_guard(Some(Arc::new(|credential| credential == "good"))),
        );
        assert!(
            stage
                .decide(
                    "/admin",
                    &[("x-request-id", "a"), ("authorization", "Bearer good")]
                )
                .is_none()
        );
        let (_, answer) = stage
            .decide(
                "/admin",
                &[("x-request-id", "a"), ("authorization", "Bearer other")],
            )
            .expect("route verifier rejected");
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);

        // Without a route verifier the global fallback decides.
        let stage = HeadersAuthStage::new(
            Some(Arc::new(|credential| credential == "global")),
            admin_guard(None),
        );
        assert!(
            stage
                .decide(
                    "/admin",
                    &[("x-request-id", "a"), ("authorization", "Bearer global")]
                )
                .is_none()
        );
        assert!(
            stage
                .decide(
                    "/admin",
                    &[("x-request-id", "a"), ("authorization", "Bearer nope")]
                )
                .is_some()
        );
    }

    #[test]
    fn an_api_key_route_reads_its_header_and_verifier() {
        let stage = HeadersAuthStage::new(
            None,
            Arc::new(|path: &str| {
                (path == "/ingest").then(|| {
                    Arc::new(RouteGuard {
                        rules: HeaderAuthRules {
                            api_key_required: true,
                            api_key_header: Some("X-Key".to_owned()),
                            ..HEADER_ONLY
                        },
                        verifier: None,
                        api_key_verifier: Some(Arc::new(|credential| credential == "k-1")),
                    })
                })
            }),
        );
        assert!(stage.decide("/ingest", &[("X-Key", "k-1")]).is_none());
        let (violation, answer) = stage.decide("/ingest", &[]).expect("missing key");
        assert_eq!(violation, GuardViolation::RequireAuth);
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        let (_, answer) = stage
            .decide("/ingest", &[("X-Key", "nope")])
            .expect("rejected");
        assert_eq!(answer.body, AUTHENTICATION_REQUIRED_BODY);
    }

    /// The future the plumbing tests drive: the stub futures are always
    /// immediately ready, so a noop-waker spin never spins.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::hint::spin_loop(),
            }
        }
    }

    /// The inner service the plumbing tests wrap: counts its calls and
    /// answers `200 "inner"`.
    #[derive(Clone)]
    struct Inner {
        calls: Arc<AtomicUsize>,
    }

    impl Inner {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ::tower::Service<Request<&'static str>> for Inner {
        type Response = Response<String>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<&'static str>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            drop(request);
            Box::pin(async move { Ok(Response::new("inner".to_owned())) })
        }
    }

    fn request_to(path: &str, headers: &[(&str, &str)]) -> Request<&'static str> {
        let mut builder = Request::builder().uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body("body").expect("request")
    }

    #[test]
    fn layer_passes_through_and_the_inner_service_answers() {
        // The presence guard passes a well-formed request without any
        // verifier configured.
        let layer = HeadersAuthStageLayer::new(stage_with(presence_guard()));
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_to(
            "/admin",
            &[("x-request-id", "abc"), ("authorization", "Bearer tok")],
        )))
        .expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), "inner");
        assert_eq!(inner.call_count(), 1);
    }

    #[test]
    fn layer_answers_the_400_without_hitting_the_inner_service() {
        let layer = HeadersAuthStageLayer::new(stage_with(presence_guard()));
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response =
            block_on(service.call(request_to("/admin", &[("authorization", "Bearer tok")])))
                .expect("ready");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.body(), "Missing required header: X-Request-ID");
        assert_eq!(inner.call_count(), 0, "the blocked request never hits it");
    }

    #[test]
    fn layer_answers_the_401_for_an_auth_failure() {
        let layer = HeadersAuthStageLayer::new(stage_with(admin_guard(None)));
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_to("/admin", &[("x-request-id", "abc")])))
            .expect("ready");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.body(), AUTHENTICATION_REQUIRED_BODY);
        assert_eq!(inner.call_count(), 0);
    }

    #[test]
    fn layer_clone_shares_the_resolver() {
        let stage = stage_with(admin_guard(None));
        let mut first = HeadersAuthStageService {
            inner: Inner::new(),
            stage: stage.clone(),
        };
        let mut second = HeadersAuthStageService {
            inner: Inner::new(),
            stage,
        };

        let response =
            block_on(first.call(request_to("/admin", &[("x-request-id", "abc")]))).expect("ready");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response =
            block_on(second.call(request_to("/admin", &[("x-request-id", "abc")]))).expect("ready");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn route_verifiers_debug_renders() {
        let verifiers = RouteVerifiers {
            auth: None,
            api_key: None,
        };
        assert!(format!("{verifiers:?}").contains("RouteVerifiers"));
    }

    #[test]
    fn stage_and_layer_debug_render_their_names() {
        let stage = stage_with(admin_guard(None));
        assert!(format!("{stage:?}").contains("HeadersAuthStage"));
        let layer = HeadersAuthStageLayer::new(stage);
        assert!(format!("{layer:?}").contains("HeadersAuthStageLayer"));
    }

    #[test]
    fn block_on_drives_a_pending_once_future() {
        struct PendingOnce {
            polled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        impl Future for PendingOnce {
            type Output = ();
            fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if !self.polled.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(())
            }
        }
        let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        block_on(PendingOnce {
            polled: std::sync::Arc::clone(&polled),
        });
    }

    #[test]
    fn the_layer_service_polls_ready() {
        let layer = HeadersAuthStageLayer::new(stage_with(admin_guard(None)));
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(Inner::new());
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let polled = ::tower::Service::<Request<&'static str>>::poll_ready(&mut service, &mut cx);
        assert!(polled.is_ready());
        assert_eq!(polled.map(|result| result.is_ok()), Poll::Ready(true));
    }
}
