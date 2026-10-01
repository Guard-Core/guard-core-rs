//! The request size and content-type pipeline stage for tower stacks.
//!
//! One `tower::Layer` that answers the reference engine's
//! `request_size_content` check
//! (`guard_core/core/checks/implementations/request_size_content.py`)
//! before a request reaches the inner service.
//!
//! The decision core is [`guard_core_engine::request_limits`]; this stage
//! wires it into the family's tower seams:
//!
//! ```text
//! route resolves to no limits (or no resolver):   pass through
//! content-length over max_request_size:           413 "Request too large"
//! media type not in allowed_content_types
//!   (a missing content-type header included):     415 "Unsupported content type"
//! content-length header is not an integer:        500 "Security check failed"
//!                                                 (the fail-secure shape)
//! everything else:                                pass through
//! ```
//!
//! ## Reference contract, point by point
//!
//! - **Route-scoped config**: both limits live on the reference
//!   `RouteConfig` (`max_request_size`, `allowed_content_types`); there is
//!   no global knob. The stage learns them through the
//!   [`RouteLimitsResolver`] seam (`path -> Option<ContentLimits>`, what the
//!   reference reads from `request.state.route_config`); a route that
//!   resolves to `None` passes, exactly the reference's `if not
//!   route_config: return None`.
//! - **Order**: the size check runs before the type check, and the stage as
//!   a whole sits where the reference pipeline runs it: after logging, before
//!   the required-headers and authentication stages, and before the
//!   IP-visible stages (`ip_security`, `cloud_provider`, `user_agent`,
//!   `rate_limit`) - install it outermost of the guard stages so an
//!   oversized request is answered `413` even when its sender is banned or
//!   throttled, as in the reference.
//! - **Fail-secure**: a non-integer `content-length` header raises inside
//!   the reference check and the pipeline answers
//!   `500 "Security check failed"` under its default `fail_secure = True`;
//!   the stage's [`decide`](RequestLimitsStage::decide) mirrors that with an
//!   `Err`, and the tower service renders the same 500 shape.
//! - **Not mirrored**: the reference emits `EVENT_CONTENT_FILTERED` events
//!   and `log_activity` entries, honors `passive_mode` (log-only), the
//!   `on_block` hook, and `custom_error_responses` body overrides. The Rust
//!   config surface has no event bus, no `passive_mode`, and no custom-body
//!   map yet; the
//!   [`guard_core_engine::request_limits::ContentBlock`] the decision core
//!   returns carries the reference reason strings for adapters that log.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_engine::request_limits::ContentLimits;
//! use guard_core_rs::request_limits::{RequestLimitsStage, RouteLimitsResolver};
//!
//! let resolver: RouteLimitsResolver = Arc::new(|path| {
//!     (path == "/upload").then(|| ContentLimits {
//!         max_request_size: Some(1024),
//!         ..ContentLimits::default()
//!     })
//! });
//! let stage = RequestLimitsStage::new(resolver);
//!
//! // A request to an unconfigured path passes; the crossing is the 413 shape.
//! assert!(stage.decide("/other", Some("999999"), None).unwrap().is_none());
//! let block = stage.decide("/upload", Some("1025"), None).unwrap().expect("blocked");
//! assert_eq!(block.status, 413);
//! assert_eq!(block.body, "Request too large");
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Request, Response, StatusCode};

pub use guard_core_engine::request_limits::{ContentLengthError, ContentLimits};

/// The stage's block answer: the status and the reference default message
/// body (the same shape the rate-limit stage answers with).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageResponse {
    /// `413` for the size block, `415` for the type block, `500` for the
    /// fail-secure shape.
    pub status: StatusCode,
    /// The reference default message body.
    pub body: &'static str,
}

/// The fail-secure answer body (`SecurityCheckPipeline`'s
/// `default_message="Security check failed"` for a check error under
/// `fail_secure = True`).
pub const FAIL_SECURE_BODY: &str = "Security check failed";

/// How the stage learns a path's content limits.
///
/// The reference reads them from `request.state.route_config`; a tower stack
/// resolves them from the request path. `None` (no entry) means the route
/// carries no limits and passes, the reference's no-decorator shape.
pub type RouteLimitsResolver = Arc<dyn Fn(&str) -> Option<ContentLimits> + Send + Sync>;

/// The request size and content-type stage over one route resolver.
///
/// Build it once at startup with [`RequestLimitsStage::new`] and install it
/// with [`RequestLimitsStageLayer`]. The stage is cheaply clonable; the
/// resolver is shared.
#[derive(Clone)]
pub struct RequestLimitsStage {
    resolver: RouteLimitsResolver,
}

impl fmt::Debug for RequestLimitsStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestLimitsStage").finish_non_exhaustive()
    }
}

impl RequestLimitsStage {
    /// Build the stage over `resolver`.
    #[must_use]
    pub fn new(resolver: RouteLimitsResolver) -> Self {
        Self { resolver }
    }

    /// One pass of the stage: `path` selects the route limits,
    /// `content_length` and `content_type` are the raw header values
    /// (`None` when a header is absent). `Ok(None)` passes; `Ok(Some(..))`
    /// is the block answer; the [`Err`] shape is the reference's
    /// non-integer `content-length` exception - render the fail-secure 500.
    ///
    /// # Errors
    ///
    /// [`ContentLengthError`] when a present, non-empty `content-length`
    /// header does not parse as an integer (the reference's `int()`
    /// `ValueError`, answered `500 "Security check failed"`).
    pub fn decide(
        &self,
        path: &str,
        content_length: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<Option<StageResponse>, ContentLengthError> {
        let Some(limits) = (self.resolver)(path) else {
            return Ok(None);
        };
        Ok(
            guard_core_engine::request_limits::decide(&limits, content_length, content_type)?.map(
                |block| StageResponse {
                    status: StatusCode::from_u16(block.status).expect("reference statuses"),
                    body: block.body,
                },
            ),
        )
    }
}

/// The `tower::Layer` carrying [`RequestLimitsStage`].
///
/// Wrap any `Service<http::Request<B>>` whose responses are
/// `http::Response<ResBody>` with `ResBody: From<&'static str>` and the
/// stage answers the reference's block shapes itself.
#[derive(Clone)]
pub struct RequestLimitsStageLayer {
    stage: RequestLimitsStage,
}

impl RequestLimitsStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: RequestLimitsStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for RequestLimitsStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestLimitsStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for RequestLimitsStageLayer {
    type Service = RequestLimitsStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLimitsStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct RequestLimitsStageService<S> {
    inner: S,
    stage: RequestLimitsStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for RequestLimitsStageService<S>
where
    S: ::tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: From<&'static str> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let path = request.uri().path().to_owned();
        let content_length = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok());
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let owned_content_length = content_length.map(str::to_owned);
        let owned_content_type = content_type.map(str::to_owned);
        let answer = self.stage.decide(
            &path,
            owned_content_length.as_deref(),
            owned_content_type.as_deref(),
        );
        let response = match answer {
            Ok(Some(block)) => render(block),
            Ok(None) => return Box::pin(self.inner.call(request)),
            Err(_) => render(StageResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: FAIL_SECURE_BODY,
            }),
        };
        drop(request);
        Box::pin(async move { Ok(response) })
    }
}

/// Render the stage's answer into the wrapped service's response body type.
fn render<ResBody: From<&'static str>>(answer: StageResponse) -> Response<ResBody> {
    let mut response = Response::new(ResBody::from(answer.body));
    *response.status_mut() = answer.status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ::tower::Service;

    fn upload_only() -> RouteLimitsResolver {
        Arc::new(|path| {
            (path == "/upload").then(|| ContentLimits {
                max_request_size: Some(1024),
                allowed_content_types: Some(vec!["application/json".to_owned()]),
            })
        })
    }

    fn stage_with(resolver: RouteLimitsResolver) -> RequestLimitsStage {
        RequestLimitsStage::new(resolver)
    }

    #[test]
    fn unconfigured_paths_pass_everything() {
        let stage = stage_with(upload_only());
        for size in ["0", "999999999", "junk", ""] {
            assert!(
                stage
                    .decide("/other", Some(size), Some("text/plain"))
                    .unwrap()
                    .is_none(),
                "content-length {size} on an unconfigured path must pass"
            );
        }
        assert!(stage.decide("/other", None, None).unwrap().is_none());
    }

    #[test]
    fn size_and_type_blocks_mirror_the_reference_shapes() {
        let stage = stage_with(upload_only());

        let pass = stage.decide("/upload", Some("1024"), Some("application/json"));
        assert!(pass.unwrap().is_none());

        let block = stage
            .decide("/upload", Some("1025"), Some("application/json"))
            .unwrap()
            .expect("over the limit");
        assert_eq!(block.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(block.body, "Request too large");

        let block = stage
            .decide("/upload", Some("10"), Some("text/plain"))
            .unwrap()
            .expect("disallowed type");
        assert_eq!(block.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(block.body, "Unsupported content type");

        // A missing content-type header is blocked by the allowed list.
        let block = stage
            .decide("/upload", Some("10"), None)
            .unwrap()
            .expect("no type");
        assert_eq!(block.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // The size check wins when both would block.
        let block = stage
            .decide("/upload", Some("2000"), Some("text/plain"))
            .unwrap()
            .expect("blocked");
        assert_eq!(block.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn junk_content_length_fails_secure() {
        let stage = stage_with(upload_only());
        let error = stage
            .decide("/upload", Some("about-twenty"), None)
            .unwrap_err();
        assert_eq!(error.value, "about-twenty");
    }

    #[test]
    fn a_route_with_no_rules_passes_oversized_requests() {
        let stage = stage_with(Arc::new(|_path| Some(ContentLimits::default())));
        assert!(
            stage
                .decide("/any", Some("999999999"), Some("text/plain"))
                .unwrap()
                .is_none()
        );
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
        type Response = Response<&'static str>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<&'static str>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            drop(request);
            Box::pin(async move { Ok(Response::new("inner")) })
        }
    }

    fn request_to(
        path: &str,
        content_length: Option<&str>,
        content_type: Option<&str>,
    ) -> Request<&'static str> {
        let mut builder = Request::builder().uri(path);
        if let Some(length) = content_length {
            builder = builder.header("content-length", length);
        }
        if let Some(kind) = content_type {
            builder = builder.header("content-type", kind);
        }
        builder.body("body").expect("request")
    }

    #[test]
    fn layer_passes_through_and_the_inner_service_answers() {
        let layer = RequestLimitsStageLayer::new(stage_with(upload_only()));
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response =
            block_on(service.call(request_to("/other", Some("999999"), None))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
        assert_eq!(inner.call_count(), 1);
        // a request without a content-length header rides the None arm
        let response = block_on(service.call(request_to("/other", None, None))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            inner.call_count(),
            2,
            "the header-less request passes through"
        );
    }

    #[test]
    fn layer_answers_the_413_without_hitting_the_inner_service() {
        let layer = RequestLimitsStageLayer::new(stage_with(upload_only()));
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response =
            block_on(service.call(request_to("/upload", Some("1025"), None))).expect("ready");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.body(), &"Request too large");
        assert_eq!(inner.call_count(), 0, "the blocked request never hits it");
    }

    #[test]
    fn layer_answers_the_415_and_reads_the_content_type() {
        let layer = RequestLimitsStageLayer::new(stage_with(upload_only()));
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response = block_on(service.call(request_to(
            "/upload",
            Some("10"),
            Some("application/json; charset=utf-8"),
        )))
        .expect("ready");
        assert_eq!(response.status(), StatusCode::OK);

        let response =
            block_on(service.call(request_to("/upload", Some("10"), Some("text/plain"))))
                .expect("ready");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(response.body(), &"Unsupported content type");
        assert_eq!(inner.call_count(), 1, "only the passing request hit it");
    }

    #[test]
    fn layer_fails_secure_on_a_junk_content_length() {
        let layer = RequestLimitsStageLayer::new(stage_with(upload_only()));
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response = block_on(service.call(request_to("/upload", Some("not-a-number"), None)))
            .expect("ready");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.body(), &FAIL_SECURE_BODY);
        assert_eq!(inner.call_count(), 0, "the failed request never hits it");
    }

    #[test]
    fn layer_clone_shares_the_resolver() {
        let stage = stage_with(upload_only());
        let mut first = RequestLimitsStageService {
            inner: Inner::new(),
            stage: stage.clone(),
        };
        let mut second = RequestLimitsStageService {
            inner: Inner::new(),
            stage,
        };

        let response =
            block_on(first.call(request_to("/upload", Some("1025"), None))).expect("ready");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response =
            block_on(second.call(request_to("/upload", Some("1025"), None))).expect("ready");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn stage_and_layer_debug_render_their_names() {
        let stage = RequestLimitsStage::new(Arc::new(|_path| None));
        assert!(format!("{stage:?}").contains("RequestLimitsStage"));
        let layer = RequestLimitsStageLayer::new(stage);
        assert!(format!("{layer:?}").contains("RequestLimitsStageLayer"));
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
        let layer = RequestLimitsStageLayer::new(RequestLimitsStage::new(Arc::new(|_path| None)));
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
