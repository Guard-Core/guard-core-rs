//! The rate-limit and dynamic-ban stage for actix-web: an actix-web
//! middleware (`Transform`) that renders the same three family shapes the
//! tower stage renders, byte-identical, by reusing
//! [`guard_core_rs::tower::RateLimitStage::decide`] as the one decision
//! point.
//!
//! The stage holds no security logic of its own: every decision is
//! [`decide`](guard_core_rs::tower::RateLimitStage::decide)'s (bans first,
//! then the throttled shape with its `Retry-After`, then the detection
//! feed), and the stores it consults are the same shared handles the tower
//! stage exposes, so an actix app and a tower app behind the same stage
//! behave identically. Install it with `App::wrap` or `Scope::wrap`:
//!
//! ```rust,ignore
//! App::new().wrap(RateLimitStageTransform::new(stage))
//! ```
//!
//! The request pieces `decide()` reads map onto actix-web as follows:
//!
//! | `decide()` input | actix-web source |
//! |---|---|
//! | client IP | [`extract_client_ip`]: the peer address, then the tower default's forwarded-header policy |
//! | skip state (`is_whitelisted`, `is_exempt`) | an `IpGateDecision` request extension, exactly what the global IP gate leaves behind |
//! | detection result | a `ThreatFinding` request extension, what a prior detection stage inserts |

use std::future::{Ready, ready};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::http::header::{HeaderMap, HeaderValue, RETRY_AFTER};
use actix_web::{HttpMessage, HttpRequest, HttpResponse};
use guard_core_rs::tower::{IpGateDecision, RateLimitStage, StageResponse, ThreatFinding};

/// The client IP the stage decides under: the peer address (the
/// deployment-controlled, spoof-proof source) when the connection carries
/// one, otherwise the same forwarded-header policy the tower default
/// applies (leftmost `x-forwarded-for` entry, then `x-real-ip`).
///
/// The policy is the tower default's, reimplemented over actix-web's header
/// types: the tower extractor speaks `http` 1.x while actix-web 4 still
/// carries `http` 0.2 types on its public surface, so the two cannot share
/// one function. Deployments behind a proxy that need a different forwarded
/// policy should terminate forwarded headers at the proxy or gate this
/// stage behind a scope of their own.
///
/// actix-web's own `ConnectionInfo::realip_remote_addr` machinery is not
/// consulted: the stage keeps one extraction policy across the family, the
/// tower default's.
pub fn extract_client_ip(request: &HttpRequest) -> Option<IpAddr> {
    if let Some(peer) = request.peer_addr() {
        return Some(peer.ip());
    }
    leftmost_forwarded(request.headers()).or_else(|| real_ip_header(request.headers()))
}

/// The leftmost `x-forwarded-for` entry (the tower default's first header
/// fallback): each entry may be a bare IP or an `ip:port` socket literal.
fn leftmost_forwarded(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_ip_entry)
}

/// The `x-real-ip` header (the tower default's second header fallback).
fn real_ip_header(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_ip_entry)
}

/// Parse one address entry: a bare IP, or an `ip:port` / `[v6]:port` socket
/// literal whose address part is taken.
fn parse_ip_entry(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    IpAddr::from_str(entry)
        .or_else(|_| SocketAddr::from_str(entry).map(|socket| socket.ip()))
        .ok()
}

/// The actix-web middleware carrying [`RateLimitStage`].
///
/// Build the stage once at startup (fail closed on an invalid config) and
/// wrap any app or scope with it. The clone installed per worker shares the
/// window, ban, and counter stores, so all workers see one sliding window
/// per client IP.
#[derive(Clone)]
pub struct RateLimitStageTransform {
    stage: RateLimitStage,
}

impl RateLimitStageTransform {
    /// Carry `stage` into every service this middleware wraps.
    #[must_use]
    pub const fn new(stage: RateLimitStage) -> Self {
        Self { stage }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitStageTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = RateLimitStageService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitStageService {
            service,
            stage: self.stage.clone(),
        }))
    }
}

/// The stage as an actix-web `Service` around the wrapped service.
pub struct RateLimitStageService<S> {
    service: S,
    stage: RateLimitStage,
}

impl<S, B> Service<ServiceRequest> for RateLimitStageService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, request: ServiceRequest) -> Self::Future {
        // One borrowed look at the request pieces, then the single decision
        // point the family shares. The extension map sits behind a read
        // lock, so the guard lives for the decision.
        let answer = {
            let ip = extract_client_ip(request.request());
            let extensions = request.extensions();
            let gate = extensions.get::<IpGateDecision>().copied();
            let finding = extensions.get::<ThreatFinding>();
            self.stage.decide(ip, gate, finding)
        };
        if let Some(answer) = answer {
            return Box::pin(ready(Ok(render_block(request, &answer))));
        }
        let future = self.service.call(request);
        Box::pin(async move { future.await.map(ServiceResponse::map_into_left_body) })
    }
}

/// Render the stage's block answer as the family shape: the status, the bare
/// default message body, and the `Retry-After` header for the throttled
/// shape. The wrapped service never sees a blocked request. The stage's
/// status speaks `http` 1.x; actix-web 4's response types speak `http` 0.2,
/// so the adapter translates through the status number.
fn render_block<B: MessageBody + 'static>(
    request: ServiceRequest,
    answer: &StageResponse,
) -> ServiceResponse<EitherBody<B>> {
    let status =
        StatusCode::from_u16(answer.status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut http = HttpResponse::with_body(status, answer.body);
    if let Some(after) = answer.retry_after {
        http.headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(after));
    }
    ServiceResponse::new(request.into_parts().0, http.map_into_boxed_body()).map_into_right_body()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use actix_web::http::StatusCode;
    use actix_web::{App, test, web};
    use guard_core_rs::tower::{
        IpBanConfig, RATE_LIMIT_BAN_REASON, RateLimitConfig, RateLimitStageConfig,
    };

    use super::*;

    /// A fake clock: f64 unix seconds starting at `1_000.0`, advanced by
    /// `advance` (the tower stage tests' pattern).
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }

        fn clock(&self) -> guard_core_rs::tower::Clock {
            let state = self.0.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || state.load(Ordering::Relaxed) as f64)
        }
    }

    fn throttling_stage(rate_limit: u32, clock: guard_core_rs::tower::Clock) -> RateLimitStage {
        RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit,
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
            custom_error_responses: std::collections::HashMap::new(),
        })
        .clock(clock)
        .build()
        .expect("valid stage config")
    }

    /// A request the extractor reads the client IP from: the peer address
    /// actix-web carries on the connection.
    fn request_from(peer: &str) -> actix_http::Request {
        test::TestRequest::default()
            .peer_addr(socket_of(peer))
            .to_request()
    }

    /// Read a response body as text. Actix's request/response types are
    /// deliberately `!Send` (single-threaded per worker), so this helper's
    /// future is not `Send` either; the `#[actix_web::test]` runtime is
    /// single-threaded and accepts it.
    #[allow(clippy::future_not_send)]
    async fn body_of<B: MessageBody + 'static>(response: ServiceResponse<B>) -> String {
        String::from_utf8_lossy(&test::read_body(response).await).into_owned()
    }

    #[actix_web::test]
    async fn throttles_on_crossing_with_the_family_shape() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;

        let first = test::call_service(&app, request_from("192.0.2.1")).await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = test::call_service(&app, request_from("192.0.2.1")).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body_of(second).await, "Too many requests");
    }

    #[actix_web::test]
    async fn retry_after_carries_the_window() {
        let fake = FakeClock::default();
        let stage = throttling_stage(1, fake.clock());
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;

        let _ = test::call_service(&app, request_from("192.0.2.2")).await;
        let throttled = test::call_service(&app, request_from("192.0.2.2")).await;
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            throttled
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("60"),
            "Retry-After is the window"
        );

        // Past the window the budget is whole again (fake clock, no sleep).
        fake.advance(61);
        let restored = test::call_service(&app, request_from("192.0.2.2")).await;
        assert_eq!(restored.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn ban_answers_first_and_never_reaches_the_handler() {
        let stage = throttling_stage(10, Arc::new(guard_core_rs::tower::system_clock));
        let attacker = ip("192.0.2.3");
        stage.bans().ban_ip(attacker, 60, "x").expect("ban");
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;

        let response = test::call_service(&app, request_from("192.0.2.3")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_of(response).await, "IP address banned");
    }

    #[actix_web::test]
    async fn exempt_ip_skips_throttling_but_bans_still_answer() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let exempt = ip("192.0.2.4");
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage.clone()))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;

        let gate = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };
        for _ in 0..25 {
            let request = test::TestRequest::default()
                .peer_addr(socket_of("192.0.2.4"))
                .to_request();
            request.extensions_mut().insert(gate);
            let response = test::call_service(&app, request).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "an exempt IP is never rate limited"
            );
        }
        assert_eq!(
            stage.limiter().tracked_windows(),
            0,
            "the exempt window was never recorded"
        );

        // Bans still apply to an exempt IP: no exemption skip on the ban
        // check.
        stage.bans().ban_ip(exempt, 60, "x").expect("ban");
        let request = test::TestRequest::default()
            .peer_addr(socket_of("192.0.2.4"))
            .to_request();
        request.extensions_mut().insert(gate);
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_of(response).await, "IP address banned");
    }

    #[actix_web::test]
    async fn default_stage_throttles_at_the_reference_threshold() {
        let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("default config");
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;
        // The reference defaults: rate limiting on, 10 requests per 60 s
        // window per IP, so the first ten pass and the eleventh throttles.
        for _ in 0..10 {
            let response = test::call_service(&app, request_from("192.0.2.5")).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let throttled = test::call_service(&app, request_from("192.0.2.5")).await;
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[actix_web::test]
    async fn peer_address_is_the_identity_the_stage_throttles_under() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;

        // Two distinct peers each keep their own budget.
        let _ = test::call_service(&app, request_from("192.0.2.6")).await;
        let first = test::call_service(&app, request_from("192.0.2.6")).await;
        assert_eq!(first.status(), StatusCode::TOO_MANY_REQUESTS);
        let other = test::call_service(&app, request_from("192.0.2.7")).await;
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn forwarded_headers_identity_when_no_peer_address_exists() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;

        let request = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "198.51.100.7, 10.0.0.1"))
            .to_request();
        let first = test::call_service(&app, request).await;
        assert_eq!(first.status(), StatusCode::OK);

        let request = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "198.51.100.7, 10.0.0.1"))
            .to_request();
        let second = test::call_service(&app, request).await;
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the leftmost forwarded entry is the client identity"
        );

        // A junk forwarded header is not a client: the request passes, and
        // repeatedly so.
        for _ in 0..5 {
            let request = test::TestRequest::default()
                .insert_header(("x-forwarded-for", "not-an-ip"))
                .to_request();
            assert_eq!(
                test::call_service(&app, request).await.status(),
                StatusCode::OK
            );
        }
    }

    #[actix_web::test]
    async fn auto_ban_feed_fires_on_the_crossing_and_the_next_request_is_banned() {
        let fake = FakeClock::default();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                enable_rate_limit_auto_ban: true,
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            passive_mode: false,
            custom_error_responses: std::collections::HashMap::new(),
        })
        .clock(fake.clock())
        .build()
        .expect("valid stage config");
        let app = test::init_service(
            App::new()
                .route("/health", web::get().to(|| async { "ok" }))
                .service(
                    web::scope("")
                        .wrap(RateLimitStageTransform::new(stage.clone()))
                        .route("/", web::get().to(|| async { "hello" })),
                ),
        )
        .await;
        let attacker = "192.0.2.8";

        // The crossing request gets the 429 while the ban fires underneath.
        let _ = test::call_service(&app, request_from(attacker)).await;
        let crossing = test::call_service(&app, request_from(attacker)).await;
        assert_eq!(crossing.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(stage.bans().is_banned(ip(attacker)));
        assert_eq!(
            stage
                .bans()
                .ban_record(ip(attacker))
                .expect("record")
                .reason,
            RATE_LIMIT_BAN_REASON
        );

        // The next request meets the ban check first: the banned shape.
        let next = test::call_service(&app, request_from(attacker)).await;
        assert_eq!(next.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_of(next).await, "IP address banned");
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    fn socket_of(text: &str) -> SocketAddr {
        SocketAddr::from_str(&format!("{text}:65535")).expect("test socket")
    }
}
