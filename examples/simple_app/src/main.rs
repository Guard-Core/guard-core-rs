//! Binary entry point for the minimal guarded service example; the
//! application itself lives in the library crate so the integration tests
//! can drive it end to end.

use guard_core_rs_simple_app::{App, BodyMapped, DEFAULT_ADDR, GuardService, Router};
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

    let app = App {
        guarded: GuardService { inner: Router },
    };

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {addr}: {error}"));
    eprintln!("guard-core-rs simple app listening on {addr}");

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
