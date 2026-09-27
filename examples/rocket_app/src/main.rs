//! Guarded Rocket service: the rate-limit and dynamic-ban stage installed as
//! a request guard with its fairing and catchers, with the decision
//! delegated to [`guard_core_rs::tower::RateLimitStage::decide`] so behavior
//! is byte-identical to the tower stage.
//!
//! Routes:
//!
//! | Route | Guard | Behavior |
//! |---|---|---|
//! | `GET /health` | none | `200 ok`, never throttled |
//! | `GET /` | guarded | `200` greeting, or the stage's 429/403 shapes |
//!
//! Exclusion is expressed as guarding (`/health` simply takes no guard
//! argument), the Rocket idiom for the reference engine's excluded paths.
//! All security decisions come from the engine stage; this app holds none.

use guard_core_rs::tower::{IpBanConfig, RateLimitConfig, RateLimitStage, RateLimitStageConfig};
use rocket::get;
use rocket::launch;
use rocket::routes;

mod stage;

use stage::{RateLimitFairing, RateLimitGuard};

/// The application listen address, overridable for container runs.
const DEFAULT_ADDR: &str = "0.0.0.0:8080";

#[get("/health")]
const fn health() -> &'static str {
    "ok\n"
}

#[get("/")]
const fn hello(_guard: RateLimitGuard) -> &'static str {
    "guard-core-rs rocket app\n"
}

#[launch]
fn rocket() -> _ {
    // Opt-in stage config: throttling on with the reference thresholds
    // (10 requests / 60 s), banning off. The same `RateLimitStage` type the
    // tower layer takes; trusted proxies, custom extraction, and an injected
    // clock all come along through its builder.
    let stage = RateLimitStage::new(RateLimitStageConfig {
        rate_limit: RateLimitConfig {
            enable_rate_limiting: true,
            ..RateLimitConfig::default()
        },
        ip_ban: IpBanConfig::default(),
        passive_mode: false,
        custom_error_responses: std::collections::HashMap::new(),
    })
    .expect("valid stage config");

    let addr: std::net::SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_owned())
        .parse()
        .unwrap_or_else(|error| panic!("APP_ADDR must be a socket address: {error}"));

    rocket::custom(
        rocket::Config::figment()
            .merge(("address", addr.ip().to_string()))
            .merge(("port", addr.port())),
    )
    // The fairing manages the stage and registers the 403/429/500 catchers
    // the guard's error outcomes dispatch to.
    .attach(RateLimitFairing::new(stage))
    .mount("/", routes![health, hello])
}
