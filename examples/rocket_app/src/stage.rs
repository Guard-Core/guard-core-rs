//! The rate-limit and dynamic-ban stage for Rocket: a request guard that
//! renders the same three family shapes the tower stage renders,
//! byte-identical, by reusing
//! [`guard_core_rs::tower::RateLimitStage::decide`] as the one decision
//! point, plus the fairing that installs it.
//!
//! The stage holds no security logic of its own: every decision is
//! [`decide`](guard_core_rs::tower::RateLimitStage::decide)'s (bans first,
//! then the throttled shape with its `Retry-After`, then the detection
//! feed), and the stores it consults are the same shared handles the tower
//! stage exposes, so a Rocket app and a tower app behind the same stage
//! behave identically.
//!
//! Rocket guards cannot respond directly: an error outcome is dispatched to
//! the error catcher for its status. The guard therefore stashes the block
//! answer in request-local state and
//! [`RateLimitFairing`] registers the `403`/`429` catchers that render it
//! (the `rocket-guard-rs` adapter's pattern). Every refusal carries the
//! ecosystem's error shape: the bare default message,
//! `text/plain; charset=utf-8`, with the `Retry-After` header on the
//! throttled shape.
//!
//! The request pieces `decide()` reads map onto Rocket as follows:
//!
//! | `decide()` input | Rocket source |
//! |---|---|
//! | client IP | `Request::client_ip()`: the `ip_header` value (`X-Real-IP` by default) when present and parseable, else the remote peer |
//! | skip state (`is_whitelisted`, `is_exempt`) | an `Option<IpGateDecision>` request-local cache entry, what a global IP gate stage leaves behind |
//! | detection result | an `Option<ThreatFinding>` request-local cache entry, what a prior detection stage inserts |
//!
//! # Extraction caveat
//!
//! Rocket's own trusted-proxies posture differs from the tower default:
//! `client_ip()` prefers the configured `ip_header` over the remote peer,
//! so a direct-exposure deployment that keeps the default `X-Real-IP` lets
//! any client spoof its throttling identity with a header. Direct-exposure
//! deployments should disable the header (`ip_header = ""` in Rocket
//! config) so the peer address decides; proxied deployments keep it and
//! strip the header at the edge. Rocket has no per-request trusted-proxy
//! gate on this read, and the stage does not second-guess the framework:
//! the trusted-proxy seam that matters for the ban engine's self-DoS
//! refusal stays on the stage builder
//! (`RateLimitStage::builder(..).trusted_proxies(..)`).

use std::io::Cursor;

use guard_core_rs::tower::{IpGateDecision, RateLimitStage, StageResponse, ThreatFinding};
use rocket::catcher::{BoxFuture, Catcher};
use rocket::fairing::{self, Fairing, Info, Kind};
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::Response;
use rocket::{Build, Rocket};

/// The fail-secure answer: the stage is not running (no managed state), so
/// the request is refused rather than passed uninspected.
fn fail_secure() -> StageAnswer {
    StageAnswer {
        body: "Security check failed".to_owned(),
        retry_after: None,
    }
}

/// Minimal default bodies for statuses a catcher receives without any
/// stashed stage answer (a `403`/`429`/`500` that did not come from this
/// stage). Rocket's own default catcher is `pub(crate)`, so there is no way
/// to delegate to it; these keep the status (and content type) honest
/// without trying to reproduce Rocket's templated pages.
const DEFAULT_403: &str = "403 Forbidden";
const DEFAULT_429: &str = "429 Too Many Requests";
const DEFAULT_500: &str = "500 Internal Server Error";

/// A block answer stashed in request-local state for the catchers to
/// render: the family shape (bare default body, optional `Retry-After`
/// seconds). The status travels through the guard's error outcome, so it is
/// not carried here twice.
#[derive(Debug, Clone)]
struct StageAnswer {
    body: String,
    retry_after: Option<u64>,
}

impl From<&StageResponse> for StageAnswer {
    fn from(answer: &StageResponse) -> Self {
        Self {
            // The custom_error_responses body override wins over the
            // family default, exactly the reference response factory.
            body: answer
                .custom_body
                .clone()
                .unwrap_or_else(|| answer.body.to_owned()),
            retry_after: answer.retry_after,
        }
    }
}

/// The Rocket fairing carrying [`RateLimitStage`]: at ignite it manages the
/// stage (the guard's source) and registers the `403`/`429`/`500` catchers
/// the guard's error outcomes dispatch to.
pub struct RateLimitFairing {
    stage: RateLimitStage,
}

impl RateLimitFairing {
    /// Carry `stage` into the app this fairing attaches to.
    #[must_use]
    pub const fn new(stage: RateLimitStage) -> Self {
        Self { stage }
    }
}

#[rocket::async_trait]
impl Fairing for RateLimitFairing {
    fn info(&self) -> Info {
        Info {
            name: "guard-core-rs rate limit stage",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> fairing::Result {
        Ok(rocket
            .manage(self.stage.clone())
            .register("/", stage_catchers()))
    }
}

/// The enforcement guard: add it as an argument to every guarded route.
///
/// ```rust,ignore
/// #[get("/")]
/// fn hello(_guard: rocket_app_stage::RateLimitGuard) -> &'static str { "hello" }
/// ```
///
/// On a block outcome the status is dispatched to the matching catcher
/// registered by [`RateLimitFairing`], which renders the stashed family
/// shape. Fail-secure rule: if the guard cannot find the managed stage, the
/// security system is not running, and the request is refused (`500`) with
/// the fail-secure body rather than passed uninspected.
#[derive(Debug)]
pub struct RateLimitGuard {
    _private: (),
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RateLimitGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(stage) = request.rocket().state::<RateLimitStage>() else {
            stash(request, fail_secure());
            return Outcome::Error((Status::InternalServerError, ()));
        };

        // One request-local read for the pieces a prior stage may have left,
        // then the single decision point the family shares.
        let ip = request.client_ip();
        let gate = *request.local_cache::<Option<IpGateDecision>, _>(|| None);
        let finding = request
            .local_cache::<Option<ThreatFinding>, _>(|| None)
            .clone();
        let Some(answer) = stage.decide(ip, gate, finding.as_ref()) else {
            return Outcome::Success(Self { _private: () });
        };
        let status =
            Status::from_code(answer.status.as_u16()).unwrap_or(Status::InternalServerError);
        stash(request, StageAnswer::from(&answer));
        Outcome::Error((status, ()))
    }
}

/// Stash a block answer for the catchers (request-local, keyed by type).
fn stash(request: &Request<'_>, answer: StageAnswer) {
    request.local_cache(|| Some(answer));
}

/// The catchers this stage registers, scoped to the base the fairing passes
/// them to. Register them manually instead when the application attaches no
/// fairing but uses [`RateLimitGuard`]:
///
/// ```rust,ignore
/// rocket::build().register("/", guard_core_rs_rocket_app::stage::stage_catchers())
/// ```
#[must_use]
pub fn stage_catchers() -> Vec<Catcher> {
    vec![
        Catcher::new(403, render_stashed),
        Catcher::new(429, render_stashed),
        Catcher::new(500, render_stashed),
    ]
}

/// The catcher handler: the stashed family shape when this stage blocked
/// the request, a minimal default body otherwise.
fn render_stashed<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    let answer = request.local_cache::<Option<StageAnswer>, _>(|| None);
    let (body, retry_after) = answer.as_ref().map_or_else(
        || (default_body(status).to_owned(), None),
        |answer| (answer.body.clone(), answer.retry_after),
    );
    Box::pin(async move {
        let mut build = Response::build();
        build.status(status).header(ContentType::Plain);
        if let Some(after) = retry_after {
            build.raw_header("Retry-After", after.to_string());
        }
        build.sized_body(body.len(), Cursor::new(body)).ok()
    })
}

/// The minimal honest body for a status without a stashed stage answer.
const fn default_body(status: Status) -> &'static str {
    match status.code {
        403 => DEFAULT_403,
        429 => DEFAULT_429,
        _ => DEFAULT_500,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use guard_core_rs::tower::{
        Clock, IpBanConfig, RATE_LIMIT_BAN_REASON, RateLimitConfig, RateLimitStageConfig,
    };
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::{Client, LocalResponse};
    use rocket::{get, routes};

    use super::*;

    #[get("/health")]
    fn unguarded() -> &'static str {
        "ok"
    }

    #[get("/")]
    fn guarded(_guard: RateLimitGuard) -> &'static str {
        "hello"
    }

    /// A fake clock: f64 unix seconds starting at `1_000.0`, advanced by
    /// `advance` (the tower stage tests' pattern).
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }

        fn clock(&self) -> Clock {
            let state = self.0.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || state.load(Ordering::Relaxed) as f64)
        }
    }

    fn throttling_stage(rate_limit: u32, clock: Clock) -> RateLimitStage {
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

    async fn client_with(stage: RateLimitStage) -> Client {
        let rocket = rocket::build()
            .attach(RateLimitFairing::new(stage))
            .mount("/", routes![unguarded, guarded]);
        Client::tracked(rocket).await.expect("valid rocket")
    }

    fn remote_of(ip_text: &str) -> SocketAddr {
        SocketAddr::from_str(&format!("{ip_text}:65535")).expect("test socket")
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    async fn body_of(response: LocalResponse<'_>) -> String {
        response.into_string().await.expect("plain text body")
    }

    #[rocket::async_test]
    async fn throttles_on_crossing_with_the_family_shape() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let client = client_with(stage).await;

        let first = client
            .get("/")
            .remote(remote_of("192.0.2.1"))
            .dispatch()
            .await;
        assert_eq!(first.status(), Status::Ok);
        assert_eq!(body_of(first).await, "hello");

        let second = client
            .get("/")
            .remote(remote_of("192.0.2.1"))
            .dispatch()
            .await;
        assert_eq!(second.status(), Status::TooManyRequests);
        assert_eq!(body_of(second).await, "Too many requests");
    }

    #[rocket::async_test]
    async fn retry_after_carries_the_window_and_the_budget_restores() {
        let fake = FakeClock::default();
        let stage = throttling_stage(1, fake.clock());
        let client = client_with(stage).await;

        let _ = client
            .get("/")
            .remote(remote_of("192.0.2.2"))
            .dispatch()
            .await;
        let throttled = client
            .get("/")
            .remote(remote_of("192.0.2.2"))
            .dispatch()
            .await;
        assert_eq!(throttled.status(), Status::TooManyRequests);
        assert_eq!(
            throttled.headers().get_one("Retry-After"),
            Some("60"),
            "Retry-After is the window"
        );

        // Past the window the budget is whole again (fake clock, no sleep).
        fake.advance(61);
        let restored = client
            .get("/")
            .remote(remote_of("192.0.2.2"))
            .dispatch()
            .await;
        assert_eq!(restored.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn ban_answers_first_and_never_reaches_the_handler() {
        let stage = throttling_stage(10, Arc::new(guard_core_rs::tower::system_clock));
        let attacker = ip("192.0.2.3");
        stage.bans().ban_ip(attacker, 60, "x").expect("ban");
        let client = client_with(stage).await;

        let response = client
            .get("/")
            .remote(remote_of("192.0.2.3"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(body_of(response).await, "IP address banned");
    }

    #[rocket::async_test]
    async fn exempt_ip_skips_throttling_but_bans_still_answer() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let exempt = ip("192.0.2.4");
        let client = client_with(stage.clone()).await;
        let gate = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };

        for _ in 0..25 {
            let request = client.get("/").remote(remote_of("192.0.2.4"));
            request.inner().local_cache(|| Some(gate));
            let response = request.dispatch().await;
            assert_eq!(
                response.status(),
                Status::Ok,
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
        let request = client.get("/").remote(remote_of("192.0.2.4"));
        request.inner().local_cache(|| Some(gate));
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(body_of(response).await, "IP address banned");
    }

    #[rocket::async_test]
    async fn default_stage_throttles_at_the_reference_threshold() {
        let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("default config");
        let client = client_with(stage).await;
        // The reference defaults: rate limiting on, 10 requests per 60 s
        // window per IP, so the first ten pass and the eleventh throttles.
        for _ in 0..10 {
            let response = client
                .get("/")
                .remote(remote_of("192.0.2.5"))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        }
        let throttled = client
            .get("/")
            .remote(remote_of("192.0.2.5"))
            .dispatch()
            .await;
        assert_eq!(throttled.status(), Status::TooManyRequests);
    }

    #[rocket::async_test]
    async fn remote_peer_is_the_identity_when_no_ip_header_is_present() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let client = client_with(stage).await;

        // Two distinct remotes each keep their own budget.
        let _ = client
            .get("/")
            .remote(remote_of("192.0.2.6"))
            .dispatch()
            .await;
        let throttled = client
            .get("/")
            .remote(remote_of("192.0.2.6"))
            .dispatch()
            .await;
        assert_eq!(throttled.status(), Status::TooManyRequests);
        let other = client
            .get("/")
            .remote(remote_of("192.0.2.7"))
            .dispatch()
            .await;
        assert_eq!(other.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn ip_header_wins_over_the_remote_as_rocket_configures() {
        let stage = throttling_stage(1, Arc::new(guard_core_rs::tower::system_clock));
        let client = client_with(stage).await;

        // The same remote, different X-Real-IP identities: the header value
        // (Rocket's default `ip_header`) decides the throttling identity,
        // which is the framework's configured posture, not the stage's.
        let _ = client
            .get("/")
            .remote(remote_of("192.0.2.8"))
            .header(Header::new("X-Real-IP", "198.51.100.7"))
            .dispatch()
            .await;
        let second = client
            .get("/")
            .remote(remote_of("192.0.2.8"))
            .header(Header::new("X-Real-IP", "198.51.100.7"))
            .dispatch()
            .await;
        assert_eq!(
            second.status(),
            Status::TooManyRequests,
            "the header identity is the throttled one"
        );

        // The bare remote never saw a cross, so it still passes.
        let bare = client
            .get("/")
            .remote(remote_of("192.0.2.8"))
            .dispatch()
            .await;
        assert_eq!(bare.status(), Status::Ok);

        // A malformed header value is no identity at all: the remote's own
        // budget applies (it is fresh, so the request passes).
        let malformed = client
            .get("/")
            .remote(remote_of("192.0.2.9"))
            .header(Header::new("X-Real-IP", "not-an-ip"))
            .dispatch()
            .await;
        assert_eq!(malformed.status(), Status::Ok);
    }

    #[rocket::async_test]
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
        let client = client_with(stage.clone()).await;

        // The crossing request gets the 429 while the ban fires underneath.
        let _ = client
            .get("/")
            .remote(remote_of("203.0.113.1"))
            .dispatch()
            .await;
        let crossing = client
            .get("/")
            .remote(remote_of("203.0.113.1"))
            .dispatch()
            .await;
        assert_eq!(crossing.status(), Status::TooManyRequests);
        assert!(stage.bans().is_banned(ip("203.0.113.1")));
        assert_eq!(
            stage
                .bans()
                .ban_record(ip("203.0.113.1"))
                .expect("record")
                .reason,
            RATE_LIMIT_BAN_REASON
        );

        // The next request meets the ban check first: the banned shape.
        let next = client
            .get("/")
            .remote(remote_of("203.0.113.1"))
            .dispatch()
            .await;
        assert_eq!(next.status(), Status::Forbidden);
        assert_eq!(body_of(next).await, "IP address banned");
    }
}
