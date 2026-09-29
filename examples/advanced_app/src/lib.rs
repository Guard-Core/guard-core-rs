//! Library surface for the advanced guarded service example.
//!
//! Production-shaped guarded service.
//!
//! Differences from `simple_app`:
//!
//! - The engine [`DetectConfig`] and the body cap are driven by environment
//!   variables (see `env_config` below), so a deployment tunes detection
//!   without a rebuild.
//! - Route-scoped guard configuration: `/admin/*` traffic is screened by a
//!   second, stricter guard tree (lower threat-score and semantic
//!   thresholds), while general routes use the default-derived config.
//! - `/health` stays in front of both guards, mirroring excluded-path
//!   behavior.
//!
//! The guard-core-rs engine currently ships the CPU-bound detection pipeline
//! only: there is no rate limiter, ban manager, or Redis surface to drive,
//! so this example scopes guard configuration per route tree and stops
//! there.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use guard_core_rs::detect::{self, DetectConfig};
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use percent_encoding::percent_decode_str;
use tower::Service;

/// The application listen address.
pub const DEFAULT_ADDR: &str = "0.0.0.0:8080";

/// Block response bodies, matching the reference engine's default messages.
const SUSPICIOUS_BODY: &str = "{\"detail\":\"Suspicious activity detected\"}";
const PAYLOAD_TOO_LARGE_BODY: &str = "{\"detail\":\"Payload too large\"}";

/// Engine knobs mirroring the conformance corpus defaults.
pub const DEFAULT_CONFIG: DetectConfig = DetectConfig {
    max_content_length: 10_000,
    max_full_scan_bytes: 262_144,
    preserve_attack_patterns: true,
    semantic_threshold: 0.7,
    threat_score_threshold: 1.0,
    binary_min_run_length: 16,
};

/// Request body handed to the guards: wire body or rebuilt buffered bytes.
pub enum AppBody {
    /// The body as it arrived from the socket.
    Wire(Incoming),
    /// A body rebuilt from buffered bytes (or an empty body).
    Buffered(Full<Bytes>),
}

impl Body for AppBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Wire(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map_err(|error| Box::new(error) as Self::Error),
            Self::Buffered(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map_err(|error: Infallible| match error {}),
        }
    }
}

impl From<Bytes> for AppBody {
    fn from(bytes: Bytes) -> Self {
        Self::Buffered(Full::new(bytes))
    }
}

/// The application: two guarded route trees behind one path dispatcher.
#[derive(Clone)]
pub struct App {
    pub general: GuardService<Router>,
    pub admin: GuardService<AdminRouter>,
}

impl Service<Request<AppBody>> for App {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.general.poll_ready(cx)?.is_pending() {
            return Poll::Pending;
        }
        self.admin.poll_ready(cx)
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        // Excluded path: answered before any guard sees the request.
        if request.uri().path() == "/health" {
            let response = plain_response(StatusCode::OK, "ok\n");
            return Box::pin(async move { Ok(response) });
        }
        if request.uri().path().starts_with("/admin") {
            return Box::pin(self.admin.call(request));
        }
        Box::pin(self.general.call(request))
    }
}

/// Maps hyper's wire body into [`AppBody`].
#[derive(Clone)]
pub struct BodyMapped {
    pub inner: App,
}

impl Service<Request<Incoming>> for BodyMapped {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = <App as Service<Request<AppBody>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        self.inner.call(request.map(AppBody::Wire))
    }
}

/// The guard shim: buffers the body, caps its size, then runs the engine's
/// detection pipeline over the path, each query parameter value, and the
/// body, each with its reference request context.
///
/// A threat verdict becomes a `400`; an over-cap body becomes a `413`. The
/// config and body cap are per-tree, which is how route-scoped guard
/// strictness is expressed here.
#[derive(Clone)]
pub struct GuardService<R> {
    pub config: DetectConfig,
    pub body_cap: usize,
    pub inner: R,
}

impl<R> Service<Request<AppBody>> for GuardService<R>
where
    R: Service<Request<AppBody>, Response = Response<Full<Bytes>>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    R::Future: Send,
{
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        let config = self.config;
        let body_cap = self.body_cap;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = body
                .collect()
                .await
                .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);

            if bytes.len() > body_cap {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    PAYLOAD_TOO_LARGE_BODY,
                ));
            }

            if is_threat(parts.uri.path(), "url_path", &config) {
                return Ok(block_response());
            }

            if let Some(query) = parts.uri.query() {
                for value in parse_query_values(query) {
                    if is_threat(&value, "query_param", &config) {
                        return Ok(block_response());
                    }
                }
            }

            if !bytes.is_empty()
                && is_threat(&String::from_utf8_lossy(&bytes), "request_body", &config)
            {
                return Ok(block_response());
            }

            let request = Request::from_parts(parts, AppBody::from(bytes));
            inner.call(request).await
        })
    }
}

/// Runs the engine's `detect` pipeline over one content slice.
fn is_threat(content: &str, source: &str, config: &DetectConfig) -> bool {
    detect::detect(content, source, config).is_threat
}

fn block_response() -> Response<Full<Bytes>> {
    json_response(StatusCode::BAD_REQUEST, SUSPICIOUS_BODY)
}

/// Splits a raw query string into percent-decoded values (keys are dropped).
fn parse_query_values(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split('=').next_back().unwrap_or(""))
        .map(|raw| percent_decode_str(raw).decode_utf8_lossy().into_owned())
        .collect()
}

/// General routes: default-derived guard configuration.
#[derive(Clone, Copy)]
pub struct Router;

impl Service<Request<AppBody>> for Router {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = body
                .collect()
                .await
                .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);
            match (parts.method, parts.uri.path()) {
                (http::Method::GET, "/") => Ok(plain_response(
                    StatusCode::OK,
                    "guard-core-rs advanced app\n",
                )),
                (http::Method::GET, "/search") => Ok(plain_response(StatusCode::OK, "search ok\n")),
                (http::Method::POST, "/echo") => Ok(plain_response_bytes(StatusCode::OK, &bytes)),
                _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found\n")),
            }
        })
    }
}

/// Admin routes: screened by the stricter `/admin` guard tree.
#[derive(Clone, Copy)]
pub struct AdminRouter;

impl Service<Request<AppBody>> for AdminRouter {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        Box::pin(async move {
            let (parts, _body) = request.into_parts();
            match (parts.method, parts.uri.path()) {
                (http::Method::GET, "/admin/stats") => {
                    Ok(plain_response(StatusCode::OK, "stats\n"))
                }
                _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found\n")),
            }
        })
    }
}

fn plain_response(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    plain_response_bytes(status, text.as_bytes())
}

fn plain_response_bytes(status: StatusCode, bytes: &[u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(bytes)))
        .expect("static response parts")
}

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("static response parts")
}

/// Build the engine [`DetectConfig`] from environment variables.
///
/// Every knob is optional; unset variables fall back to the ecosystem
/// defaults pinned in `DEFAULT_CONFIG`.
///
/// | Variable | Field | Default |
/// |---|---|---|
/// | `GUARD_MAX_CONTENT_LENGTH` | `max_content_length` | `10000` |
/// | `GUARD_MAX_FULL_SCAN_BYTES` | `max_full_scan_bytes` | `262144` |
/// | `GUARD_PRESERVE_ATTACK_PATTERNS` | `preserve_attack_patterns` | `true` |
/// | `GUARD_SEMANTIC_THRESHOLD` | `semantic_threshold` | `0.7` |
/// | `GUARD_THREAT_SCORE_THRESHOLD` | `threat_score_threshold` | `1.0` |
/// | `GUARD_BINARY_MIN_RUN_LENGTH` | `binary_min_run_length` | `16` |
#[must_use]
pub fn env_config() -> DetectConfig {
    let defaults = DEFAULT_CONFIG;
    DetectConfig {
        max_content_length: env_usize("GUARD_MAX_CONTENT_LENGTH", defaults.max_content_length),
        max_full_scan_bytes: env_usize("GUARD_MAX_FULL_SCAN_BYTES", defaults.max_full_scan_bytes),
        preserve_attack_patterns: env_bool(
            "GUARD_PRESERVE_ATTACK_PATTERNS",
            defaults.preserve_attack_patterns,
        ),
        semantic_threshold: env_f64("GUARD_SEMANTIC_THRESHOLD", defaults.semantic_threshold),
        threat_score_threshold: env_f64(
            "GUARD_THREAT_SCORE_THRESHOLD",
            defaults.threat_score_threshold,
        ),
        binary_min_run_length: env_usize(
            "GUARD_BINARY_MIN_RUN_LENGTH",
            defaults.binary_min_run_length,
        ),
    }
}

#[must_use]
pub fn env_usize(name: &str, default: usize) -> usize {
    env_usize_from(std::env::var(name).ok(), default)
}

/// The parsing core of the usize environment helper, separated from the
/// fallbacks are unit-testable (edition 2024 makes `set_var` unsafe).
#[must_use]
pub fn env_usize_from(value: Option<String>, default: usize) -> usize {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[must_use]
pub fn env_f64(name: &str, default: f64) -> f64 {
    env_f64_from(std::env::var(name).ok(), default)
}

/// The parsing core of the f64 environment helper.
#[must_use]
pub fn env_f64_from(value: Option<String>, default: f64) -> f64 {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    env_bool_from(std::env::var(name).ok(), default)
}

/// The parsing core of the boolean environment helper.
#[must_use]
pub fn env_bool_from(value: Option<String>, default: bool) -> bool {
    value.map_or(default, |value| {
        matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
    })
}
