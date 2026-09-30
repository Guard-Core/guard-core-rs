//! End-to-end tests for the minimal guarded service: the guard shim, the
//! router, and the live accept loop, driven through real requests.

use bytes::Bytes;
use guard_core_rs_simple_app::{App, AppBody, BodyMapped, GuardService, Router};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::Service;

fn buffered_request(method: http::Method, uri: &str, body: &str) -> Request<AppBody> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(AppBody::from(Bytes::copy_from_slice(body.as_bytes())))
        .expect("static request parts")
}

async fn call(app: &mut App, request: Request<AppBody>) -> (StatusCode, Bytes) {
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
async fn health_is_served_in_front_of_the_guard() {
    let mut app = App {
        guarded: GuardService { inner: Router },
    };
    let (status, body) = call(&mut app, buffered_request(http::Method::GET, "/health", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ok\n");
}

#[tokio::test]
async fn the_router_answers_greeting_search_echo_and_404() {
    let mut app = App {
        guarded: GuardService { inner: Router },
    };

    let (status, body) = call(&mut app, buffered_request(http::Method::GET, "/", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"guard-core-rs simple app\n");

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

    let (status, body) = call(&mut app, buffered_request(http::Method::GET, "/nope", "")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"not found\n");
}

#[tokio::test]
async fn a_suspicious_query_parameter_is_blocked_with_the_reference_400() {
    let mut app = App {
        guarded: GuardService { inner: Router },
    };
    let (status, body) = call(
        &mut app,
        buffered_request(
            http::Method::GET,
            "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.as_ref(),
        b"{\"detail\":\"Suspicious activity detected\"}"
    );
}

#[tokio::test]
async fn a_suspicious_body_and_a_suspicious_path_are_blocked() {
    let mut app = App {
        guarded: GuardService { inner: Router },
    };

    let (status, _) = call(
        &mut app,
        buffered_request(
            http::Method::POST,
            "/echo",
            "1' UNION SELECT password FROM users--",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the body view blocks SQLi");

    let (status, _) = call(
        &mut app,
        buffered_request(http::Method::GET, "/../../etc/passwd", ""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the path view blocks traversal"
    );
}

#[tokio::test]
async fn an_over_cap_body_answers_413_without_being_forwarded() {
    let mut app = App {
        guarded: GuardService { inner: Router },
    };
    let oversized = "x".repeat(guard_core_rs_simple_app::DEFAULT_CONFIG.max_full_scan_bytes + 1);
    let (status, body) = call(
        &mut app,
        buffered_request(http::Method::POST, "/echo", &oversized),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body.as_ref(), b"{\"detail\":\"Payload too large\"}");
}

#[tokio::test]
async fn query_values_are_percent_decoded_before_the_engine_sees_them() {
    let mut app = App {
        guarded: GuardService { inner: Router },
    };
    // The percent-encoded form of `<script>alert(1)</script>`.
    let encoded = "%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    let (status, _) = call(
        &mut app,
        buffered_request(http::Method::GET, &format!("/search?q={encoded}"), ""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "decoded values reach the engine"
    );
}

#[tokio::test]
async fn the_wire_server_serves_the_same_routes_over_tcp() {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use hyper_util::service::TowerToHyperService;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = BodyMapped {
        inner: App {
            guarded: GuardService { inner: Router },
        },
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let app = app.clone();
            tokio::spawn(async move {
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                    .await;
            });
        }
    });

    // Raw HTTP/1.1 request over the socket: exercises the wire-body path.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("ok\n"), "{response}");

    // And a buffered (non-wire) body still polls cleanly through the
    // AppBody shim alongside the wire path.
    let mut app = App {
        guarded: GuardService { inner: Router },
    };
    let (status, _) = call(&mut app, buffered_request(http::Method::GET, "/health", "")).await;
    assert_eq!(status, StatusCode::OK);
}
