//! Guarded actix-web service: the rate-limit and dynamic-ban stage installed
//! as an actix-web middleware, with the decision delegated to
//! [`guard_core_rs::tower::RateLimitStage::decide`] so behavior is
//! byte-identical to the tower stage.
//!
//! Routes:
//!
//! | Route | Stage | Behavior |
//! |---|---|---|
//! | `GET /health` | outside the guarded scope | `200 ok`, never throttled |
//! | `GET /` | guarded | `200` greeting, or the stage's 429/403 shapes |
//!
//! Exclusion is expressed as routing (`/health` lives outside the wrapped
//! scope), the actix-web idiom for the reference engine's excluded paths.
//! All security decisions come from the engine stage; this app holds none.

use actix_web::{App, HttpResponse, HttpServer, web};
use guard_core_rs::tower::{IpBanConfig, RateLimitConfig, RateLimitStage, RateLimitStageConfig};

mod stage;

use stage::RateLimitStageTransform;

/// The application listen address, overridable for container runs.
const DEFAULT_ADDR: &str = "0.0.0.0:8080";

async fn hello() -> HttpResponse {
    HttpResponse::Ok().body("guard-core-rs actix app\n")
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let addr: std::net::SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_owned())
        .parse()
        .unwrap_or_else(|error| panic!("APP_ADDR must be a socket address: {error}"));

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

    let server = HttpServer::new(move || {
        App::new()
            // Unguarded: the excluded-path route lives outside the wrapped
            // scope.
            .route("/health", web::get().to(health))
            .service(
                web::scope("")
                    .wrap(RateLimitStageTransform::new(stage.clone()))
                    .route("/", web::get().to(hello)),
            )
    })
    .bind(addr)?;

    eprintln!("guard-core-rs actix app listening on {addr}");
    server.run().await
}
