//! End-to-end tests for the advanced guarded service: both guard trees,
//! the routers, the env parsing, and the live accept loop.

use guard_core_rs_advanced_app::{
    AdminRouter, App, AppBody, DEFAULT_CONFIG, GuardService, Router, env_bool_from, env_config,
    env_f64_from, env_usize_from,
};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::Service;

const fn app() -> App {
    App {
        general: GuardService {
            config: DEFAULT_CONFIG,
            body_cap: DEFAULT_CONFIG.max_full_scan_bytes,
            inner: Router,
        },
        admin: GuardService {
            config: DEFAULT_CONFIG,
            body_cap: DEFAULT_CONFIG.max_full_scan_bytes,
            inner: AdminRouter,
        },
    }
}

fn buffered_request(method: http::Method, uri: &str, body: &str) -> Request<AppBody> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(AppBody::from(bytes::Bytes::copy_from_slice(
            body.as_bytes(),
        )))
        .expect("static request parts")
}

async fn call(app: &mut App, request: Request<AppBody>) -> (StatusCode, bytes::Bytes) {
    let response = app
        .call(request)
        .await
        .expect("the app never fails internally");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("in-memory body")
        .to_bytes();
    (status, body)
}

#[tokio::test]
async fn health_is_answered_before_any_guard() {
    let mut app = app();
    let (status, body) = call(&mut app, buffered_request(http::Method::GET, "/health", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ok\n");
}

#[tokio::test]
async fn the_general_router_answers_all_routes() {
    let mut app = app();

    let (status, body) = call(&mut app, buffered_request(http::Method::GET, "/", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"guard-core-rs advanced app\n");

    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::GET, "/search?q=x", ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"search ok\n");

    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::POST, "/echo", "ping"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ping");

    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::GET, "/missing", ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"not found\n");
}

#[tokio::test]
async fn the_admin_router_serves_stats_under_the_admin_guard() {
    let mut app = app();

    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::GET, "/admin/stats", ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"stats\n");

    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::GET, "/admin/other", ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"not found\n");
}

#[tokio::test]
async fn both_guard_trees_block_suspicious_traffic() {
    let mut app = app();

    let (status, body) = call(
        &mut app,
        buffered_request(
            http::Method::GET,
            "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
            "",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the general tree blocks SQLi"
    );
    assert_eq!(
        body.as_ref(),
        b"{\"detail\":\"Suspicious activity detected\"}"
    );

    let (status, _) = call(
        &mut app,
        buffered_request(
            http::Method::GET,
            "/admin/stats?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the admin tree blocks XSS");

    let (status, _) = call(
        &mut app,
        buffered_request(
            http::Method::POST,
            "/admin/stats",
            "1' UNION SELECT password FROM users--",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the admin tree blocks SQLi bodies"
    );

    let (status, _) = call(
        &mut app,
        buffered_request(http::Method::GET, "/admin/../../etc/passwd", ""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the admin tree blocks traversal"
    );
}

#[tokio::test]
async fn an_over_cap_body_answers_413_without_being_forwarded() {
    let mut app = app();
    let oversized = "x".repeat(DEFAULT_CONFIG.max_full_scan_bytes + 1);
    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::POST, "/echo", &oversized),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body.as_ref(), b"{\"detail\":\"Payload too large\"}");
}

#[tokio::test]
async fn a_smaller_body_cap_answers_413_earlier() {
    let mut app = App {
        general: GuardService {
            config: DEFAULT_CONFIG,
            body_cap: 16,
            inner: Router,
        },
        admin: GuardService {
            config: DEFAULT_CONFIG,
            body_cap: 16,
            inner: AdminRouter,
        },
    };
    let (status, _) = call(
        &mut app,
        buffered_request(http::Method::POST, "/echo", "x".repeat(17).as_str()),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = call(
        &mut app,
        buffered_request(http::Method::POST, "/echo", "within cap"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn env_parsing_cores_cover_every_fallback() {
    assert_eq!(env_usize_from(None, 5), 5);
    assert_eq!(env_usize_from(Some("12".to_owned()), 5), 12);
    assert_eq!(env_usize_from(Some("junk".to_owned()), 5), 5);

    assert!((env_f64_from(None, 0.7) - 0.7).abs() < f64::EPSILON);
    assert!((env_f64_from(Some("0.25".to_owned()), 0.7) - 0.25).abs() < f64::EPSILON);
    assert!((env_f64_from(Some("bad".to_owned()), 0.7) - 0.7).abs() < f64::EPSILON);

    assert!(env_bool_from(None, true));
    assert!(!env_bool_from(None, false));
    assert!(env_bool_from(Some("1".to_owned()), false));
    assert!(env_bool_from(Some("TRUE".to_owned()), false));
    assert!(env_bool_from(Some("yes".to_owned()), false));
    assert!(!env_bool_from(Some("off".to_owned()), false));
}

#[test]
fn env_config_with_an_unset_environment_matches_the_defaults() {
    // Nothing sets the GUARD_* variables in the test process, so the
    // computed config equals the pinned defaults.
    let config = env_config();
    assert_eq!(config.max_content_length, DEFAULT_CONFIG.max_content_length);
    assert_eq!(
        config.max_full_scan_bytes,
        DEFAULT_CONFIG.max_full_scan_bytes
    );
    assert_eq!(
        config.preserve_attack_patterns,
        DEFAULT_CONFIG.preserve_attack_patterns
    );
    assert!((config.semantic_threshold - DEFAULT_CONFIG.semantic_threshold).abs() < f64::EPSILON);
    assert!(
        (config.threat_score_threshold - DEFAULT_CONFIG.threat_score_threshold).abs()
            < f64::EPSILON
    );
    assert_eq!(
        config.binary_min_run_length,
        DEFAULT_CONFIG.binary_min_run_length
    );
}
