//! Library surface for the minimal guarded service example.
//!
//! Minimal guarded service: a tiny hand-rolled router wrapped in a
//! hand-rolled guard shim that runs the [`guard_core_rs::detect`] pipeline
//! over every request, served over hyper.
//!
//! Routes:
//!
//! | Route | Guard | Behavior |
//! |---|---|---|
//! | `GET /health` | excluded | `200 ok`, served before the guard |
//! | `GET /` | guarded | `200` greeting |
//! | `GET /search?q=...` | guarded | `200`, or `400` when a query param trips the engine |
//! | `POST /echo` | guarded | echoes the body, or `400`/`413` from the guard |
//! | anything else | guarded | `404 not found` |
//!
//! The guard shim is the wiring an adapter performs: translate the native
//! request into engine inputs (path, query params, body), call
//! [`detect`] with the matching request context, and
//! translate a threat verdict into a block response. All security decisions
//! come from the engine; the shim itself holds no detection logic.
//!
//! The `/health` branch runs before the guard, mirroring excluded-path
//! behavior.
//!
//! guard-core-rs currently ships the CPU-bound detection pipeline only:
//! there is no rate limiter, ban manager, or Redis surface to drive, so the
//! smoke surface is detection (400) and the body cap (413) alone.

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

/// The application listen address, overridable for container runs.
pub const DEFAULT_ADDR: &str = "0.0.0.0:8080";

/// Engine knobs mirroring the conformance corpus defaults.
pub const DEFAULT_CONFIG: DetectConfig = DetectConfig {
    max_content_length: 10_000,
    max_full_scan_bytes: 262_144,
    preserve_attack_patterns: true,
    semantic_threshold: 0.7,
    threat_score_threshold: 1.0,
    binary_min_run_length: 16,
    max_scan_values: 512,
    max_scan_chars: 65_536,
    max_json_depth: 32,
};

/// Block response bodies, matching the reference engine's default messages.
const SUSPICIOUS_BODY: &str = "{\"detail\":\"Suspicious activity detected\"}";
const PAYLOAD_TOO_LARGE_BODY: &str = "{\"detail\":\"Payload too large\"}";

/// Request body handed to the guard: wire body or rebuilt buffered bytes.
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

/// The guarded application: the router wrapped in the guard layer, plus the
/// unguarded `/health` branch in front of it.
#[derive(Clone)]
pub struct App {
    pub guarded: GuardService<Router>,
}

impl Service<Request<AppBody>> for App {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.guarded.poll_ready(cx)
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        // Excluded path: answered before the guard sees the request.
        if request.uri().path() == "/health" {
            let response = plain_response(StatusCode::OK, "ok\n");
            return Box::pin(async move { Ok(response) });
        }
        Box::pin(self.guarded.call(request))
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
/// A threat verdict becomes the reference's
/// `400 "Suspicious activity detected"`; an over-cap body becomes a `413`.
#[derive(Clone)]
pub struct GuardService<R> {
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
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = body
                .collect()
                .await
                .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);

            // Body cap: reject over-cap bodies instead of forwarding them
            // unscanned (the wire-level cap an adapter enforces before the
            // engine's `max_full_scan_bytes` truncation applies).
            if bytes.len() > DEFAULT_CONFIG.max_full_scan_bytes {
                return Ok(plain_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    PAYLOAD_TOO_LARGE_BODY,
                ));
            }

            // Path view.
            if is_threat(parts.uri.path(), "url_path") {
                return Ok(block_response());
            }

            // Query parameter view.
            if let Some(query) = parts.uri.query() {
                for value in parse_query_values(query) {
                    if is_threat(&value, "query_param") {
                        return Ok(block_response());
                    }
                }
            }

            // Body view (only for bodies that carry one).
            if !bytes.is_empty() && is_threat(&String::from_utf8_lossy(&bytes), "request_body") {
                return Ok(block_response());
            }

            let request = Request::from_parts(parts, AppBody::from(bytes));
            inner.call(request).await
        })
    }
}

/// Runs the engine's `detect` pipeline over one content slice.
fn is_threat(content: &str, source: &str) -> bool {
    detect::detect(content, source, &DEFAULT_CONFIG).is_threat
}

fn block_response() -> Response<Full<Bytes>> {
    // The reference shape: 400 "Suspicious activity detected"
    // (suspicious_activity.py), not a 403.
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

/// The tiny router the guard wraps.
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
                (http::Method::GET, "/") => {
                    Ok(plain_response(StatusCode::OK, "guard-core-rs simple app\n"))
                }
                (http::Method::GET, "/search") => Ok(plain_response(StatusCode::OK, "search ok\n")),
                (http::Method::POST, "/echo") => Ok(plain_response_bytes(StatusCode::OK, &bytes)),
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
