//! Binary entry point for the advanced guarded service example; the
//! application itself lives in the library crate so the integration tests
//! can drive it end to end.

use guard_core_rs_advanced_app::{
    AdminRouter, App, BodyMapped, DEFAULT_ADDR, GuardService, Router, env_config, env_f64,
    env_usize,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let addr: std::net::SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_owned())
        .parse()
        .unwrap_or_else(|error| panic!("APP_ADDR must be a socket address: {error}"));

    let config = env_config();
    let body_cap = env_usize("GUARD_BODY_CAP", config.max_full_scan_bytes);
    // The admin tree screens with stricter thresholds: every env override
    // applies, but both score thresholds are lowered relative to the general
    // config so borderline payloads are caught on admin surface only.
    let mut admin_config = config;
    admin_config.semantic_threshold = env_f64(
        "GUARD_ADMIN_SEMANTIC_THRESHOLD",
        (config.semantic_threshold * 0.5).min(config.semantic_threshold),
    );
    admin_config.threat_score_threshold = env_f64(
        "GUARD_ADMIN_THREAT_SCORE_THRESHOLD",
        (config.threat_score_threshold * 0.5).min(config.threat_score_threshold),
    );

    let app = App {
        general: GuardService {
            config,
            body_cap,
            inner: Router,
        },
        admin: GuardService {
            config: admin_config,
            body_cap,
            inner: AdminRouter,
        },
    };

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {addr}: {error}"));
    eprintln!("guard-core-rs advanced app listening on {addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("accept failed: {error}");
                continue;
            }
        };
        let app = BodyMapped { inner: app.clone() };
        tokio::spawn(async move {
            let _ = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                .await;
        });
    }
}
