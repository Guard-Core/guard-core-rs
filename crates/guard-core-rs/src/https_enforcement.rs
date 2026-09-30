//! The HTTPS enforcement pipeline stage for tower stacks.
//!
//! One `tower::Layer` answering the reference engine's `https_enforcement`
//! check (`guard_core/core/checks/implementations/https_enforcement.py`)
//! before a request reaches the inner service.
//!
//! The decision core is [`guard_core_engine::https_enforcement`]; this
//! stage wires it into the family's tower seams:
//!
//! ```text
//! route require_https wins over the global enforce_https arm
//! plain HTTP under a requirement:  301 redirect to the https URL
//!                                  (the reference create_https_redirect)
//! passive mode:                    pass through (log-only in the reference)
//! ```
//!
//! The reference answers the redirect through its response factory and the
//! response modifier, and never fires the block hook for this check
//! (`https_enforcement` is in `ON_BLOCK_EXCLUDED_CHECK_NAMES`) - the stage
//! mirrors the exclusion by construction (it carries no hook) and renders
//! the plain `301` + `Location` shape.
//!
//! # Example
//!
//! ```
//! use guard_core_rs::https_enforcement::{HttpsEnforcementStage, HttpsEnforcementStageConfig};
//!
//! let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
//!     .enforce_https(true)
//!     .build()
//!     .expect("valid proxy list");
//!
//! // Plain HTTP under a global enforcement: a 301 to the https URL.
//! let answer = stage
//!     .decide("/", "http", None, None, "https://host.example/")
//!     .expect("redirected");
//! assert_eq!(answer.status, 301);
//! assert_eq!(answer.location, "https://host.example/");
//!
//! // HTTPS passes.
//! assert!(stage.decide("/", "https", None, None, "").is_none());
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Request, Response, StatusCode};

pub use guard_core_engine::https_enforcement::{
    HTTPS_ENFORCEMENT_CHECK_NAME, HTTPS_REDIRECT_STATUS,
};

/// The stage's answer: the reference's `create_https_redirect` shape (a
/// `301` to the scheme-upgraded URL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRedirectAnswer {
    /// `301` (`HTTPS_REDIRECT_STATUS`).
    pub status: u16,
    /// The request URL with the scheme replaced by `https` (the reference's
    /// `url_replace_scheme("https")`), composed by the caller.
    pub location: String,
}

/// How the stage learns a path's `require_https` (the reference reads it
/// from `request.state.route_config`). `None` means no route config: the
/// global arm decides. `Some(false)` opts the route out.
pub type RouteHttpsResolver = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

/// The stage configuration (`SecurityConfig.enforce_https`,
/// `.trust_x_forwarded_proto`, `.passive_mode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpsEnforcementStageConfig {
    /// The global arm, used when the route resolver has no entry.
    pub enforce_https: bool,
    /// Whether `X-Forwarded-Proto` is believed (never without a trusted
    /// connecting IP).
    pub trust_x_forwarded_proto: bool,
    /// `passive_mode`: the violation is observed, never redirected.
    pub passive_mode: bool,
}

/// The HTTPS enforcement stage.
#[derive(Clone)]
pub struct HttpsEnforcementStage {
    config: HttpsEnforcementStageConfig,
    trusted_proxies: Vec<String>,
    route_resolver: Option<RouteHttpsResolver>,
}

impl fmt::Debug for HttpsEnforcementStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsEnforcementStage")
            .field("config", &self.config)
            .field("trusted_proxies", &self.trusted_proxies.len())
            .finish_non_exhaustive()
    }
}

/// Builder for [`HttpsEnforcementStage`].
#[derive(Default)]
pub struct HttpsEnforcementStageBuilder {
    config: HttpsEnforcementStageConfig,
    trusted_proxies: Vec<String>,
    route_resolver: Option<RouteHttpsResolver>,
}

impl HttpsEnforcementStage {
    /// Start a builder over `config`.
    #[must_use]
    pub fn builder(config: HttpsEnforcementStageConfig) -> HttpsEnforcementStageBuilder {
        HttpsEnforcementStageBuilder {
            config,
            trusted_proxies: Vec::new(),
            route_resolver: None,
        }
    }

    /// One pass of the stage. `path` selects the route's `require_https`,
    /// `url_scheme` / `client_host` / `x_forwarded_proto` are the request
    /// facts the reference check reads, and `https_url` is the request URL
    /// with the scheme already swapped to `https` (the redirect target the
    /// reference's `url_replace_scheme` produces; the engine cannot see
    /// the full URL). `None` passes; `Some` is the redirect answer.
    ///
    /// # Errors
    ///
    /// A [`guard_core_engine::ip_gate::IpGateError`] naming an invalid
    /// trusted-proxy entry (config errors fail closed at the builder, so
    /// this only surfaces through [`HttpsEnforcementStageBuilder::build`]).
    pub fn decide(
        &self,
        path: &str,
        url_scheme: &str,
        client_host: Option<&str>,
        x_forwarded_proto: Option<&str>,
        https_url: &str,
    ) -> Option<HttpsRedirectAnswer> {
        let engine_config = guard_core_engine::https_enforcement::HttpsEnforcementConfig::new(
            self.config.enforce_https,
            self.config.trust_x_forwarded_proto,
            self.trusted_proxies.iter().map(String::as_str),
        )
        .expect("builder validated the proxy list");
        let route_require_https = self
            .route_resolver
            .as_ref()
            .and_then(|resolve| resolve(path));
        let request = guard_core_engine::https_enforcement::HttpsRequest {
            url_scheme,
            client_host,
            x_forwarded_proto,
            route_require_https,
        };
        match guard_core_engine::https_enforcement::decide(&request, &engine_config) {
            guard_core_engine::https_enforcement::HttpsVerdict::Allowed => None,
            guard_core_engine::https_enforcement::HttpsVerdict::Redirect { .. }
                if self.config.passive_mode =>
            {
                None
            }
            guard_core_engine::https_enforcement::HttpsVerdict::Redirect { .. } => {
                Some(HttpsRedirectAnswer {
                    status: HTTPS_REDIRECT_STATUS,
                    location: https_url.to_owned(),
                })
            }
        }
    }
}

impl HttpsEnforcementStageBuilder {
    /// Set the global arm.
    #[must_use]
    pub const fn enforce_https(mut self, enforce_https: bool) -> Self {
        self.config.enforce_https = enforce_https;
        self
    }

    /// Add trusted-proxy entries (bare IPs or CIDR ranges); the build
    /// fails closed on an invalid one.
    #[must_use]
    pub fn trusted_proxies<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.trusted_proxies
            .extend(entries.into_iter().map(|entry| entry.as_ref().to_owned()));
        self
    }

    /// Install the route `require_https` resolver.
    #[must_use]
    pub fn route_resolver(mut self, resolver: RouteHttpsResolver) -> Self {
        self.route_resolver = Some(resolver);
        self
    }

    /// Validate the trusted-proxy list and build the stage, failing closed.
    ///
    /// # Errors
    ///
    /// [`guard_core_engine::ip_gate::IpGateError`] naming the first
    /// invalid trusted-proxy entry.
    pub fn build(self) -> Result<HttpsEnforcementStage, guard_core_engine::ip_gate::IpGateError> {
        guard_core_engine::https_enforcement::HttpsEnforcementConfig::new(
            self.config.enforce_https,
            self.config.trust_x_forwarded_proto,
            self.trusted_proxies.iter().map(String::as_str),
        )?;
        Ok(HttpsEnforcementStage {
            config: self.config,
            trusted_proxies: self.trusted_proxies,
            route_resolver: self.route_resolver,
        })
    }
}

/// The `tower::Layer` carrying [`HttpsEnforcementStage`].
#[derive(Clone)]
pub struct HttpsEnforcementStageLayer {
    stage: HttpsEnforcementStage,
}

impl HttpsEnforcementStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: HttpsEnforcementStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for HttpsEnforcementStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsEnforcementStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for HttpsEnforcementStageLayer {
    type Service = HttpsEnforcementStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpsEnforcementStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct HttpsEnforcementStageService<S> {
    inner: S,
    stage: HttpsEnforcementStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for HttpsEnforcementStageService<S>
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
        let scheme = request.uri().scheme_str().unwrap_or("http").to_owned();
        let path = request.uri().path().to_owned();
        let host_and_port = request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_owned())
            .or_else(|| {
                request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned)
            });
        // The connecting identity the trusted-proxy arm reads: the host
        // half of the authority (or Host header), port stripped.
        let client_host = host_and_port
            .as_deref()
            .map(|host| host.rsplit(':').next().unwrap_or_default().to_owned());
        let forwarded = request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let authority = host_and_port.unwrap_or_default();
        let query = request
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        let https_url = format!("https://{authority}{path}{query}");

        let answer = self.stage.decide(
            &path,
            &scheme,
            client_host.as_deref(),
            forwarded.as_deref(),
            &https_url,
        );
        let Some(redirect) = answer else {
            return Box::pin(self.inner.call(request));
        };
        drop(request);
        let status = StatusCode::from_u16(redirect.status).expect("reference status");
        let mut response = Response::new(ResBody::from(""));
        *response.status_mut() = status;
        if let Ok(value) = http::HeaderValue::from_str(&redirect.location) {
            response.headers_mut().insert(http::header::LOCATION, value);
        }
        Box::pin(async move { Ok(response) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    use ::tower::Service;

    fn stage() -> HttpsEnforcementStage {
        HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
            .enforce_https(true)
            .build()
            .expect("valid")
    }

    fn route_stage() -> HttpsEnforcementStage {
        HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
            .enforce_https(false)
            .route_resolver(Arc::new(|path: &str| match path {
                "/secure" => Some(true),
                "/open" => Some(false),
                _ => None,
            }))
            .build()
            .expect("valid")
    }

    #[test]
    fn global_enforcement_redirects_plain_http_and_passes_https() {
        let stage = stage();
        let answer = stage
            .decide("/x", "http", None, None, "https://host/x")
            .expect("redirected");
        assert_eq!(answer.status, 301);
        assert_eq!(answer.location, "https://host/x");
        assert!(stage.decide("/x", "https", None, None, "").is_none());
    }

    #[test]
    fn the_route_verdict_wins_both_ways() {
        let stage = route_stage();
        assert!(
            stage.decide("/secure", "http", None, None, "").is_some(),
            "a route requiring https redirects even with the global arm off"
        );
        assert!(
            stage.decide("/open", "http", None, None, "").is_none(),
            "a route opting out passes even under a global arm"
        );
        assert!(
            stage.decide("/other", "http", None, None, "").is_none(),
            "no route entry and a globally-off engine passes"
        );
    }

    #[test]
    fn passive_mode_observes_without_redirecting() {
        let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig {
            enforce_https: true,
            passive_mode: true,
            ..HttpsEnforcementStageConfig::default()
        })
        .build()
        .expect("valid");
        assert!(
            stage
                .decide("/x", "http", None, None, "https://host/x")
                .is_none(),
            "passive mode never answers the redirect"
        );
    }

    #[test]
    fn a_forged_forwarded_proto_never_upgrades() {
        let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig {
            enforce_https: true,
            trust_x_forwarded_proto: true,
            ..HttpsEnforcementStageConfig::default()
        })
        .trusted_proxies(["10.0.0.0/8"])
        .build()
        .expect("valid");
        assert!(
            stage
                .decide("/x", "http", Some("203.0.113.9"), Some("https"), "")
                .is_some(),
            "an untrusted client's header is ignored"
        );
        assert!(
            stage
                .decide("/x", "http", Some("10.1.2.3"), Some("https"), "")
                .is_none(),
            "a trusted proxy's header upgrades the request"
        );
    }

    #[test]
    fn the_builder_fails_closed_on_a_bad_proxy_entry() {
        let error = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
            .trusted_proxies(["not-an-ip"])
            .build()
            .unwrap_err();
        assert_eq!(error.list, "trusted_proxies");
    }

    /// The future the plumbing tests drive.
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

    #[derive(Clone)]
    struct Inner {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Inner {
        fn new() -> Self {
            Self {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }

    impl ::tower::Service<Request<&'static str>> for Inner {
        type Response = Response<&'static str>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<&'static str>) -> Self::Future {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async move { Ok(Response::new("inner")) })
        }
    }

    fn request_to(uri: &str) -> Request<&'static str> {
        Request::builder().uri(uri).body("body").expect("request")
    }

    #[test]
    fn the_layer_redirects_http_and_forwards_https() {
        let layer = HttpsEnforcementStageLayer::new(stage());
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response =
            block_on(service.call(request_to("http://host/private?q=1"))).expect("ready");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(http::header::LOCATION)
                .expect("location"),
            "https://host/private?q=1"
        );
        assert_eq!(
            inner.calls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the redirected request never hits the inner service"
        );

        let response = block_on(service.call(request_to("https://host/private"))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
    }
}
