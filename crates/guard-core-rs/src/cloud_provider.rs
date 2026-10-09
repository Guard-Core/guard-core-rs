//! The cloud-provider blocking pipeline stage for tower stacks.
//!
//! One `tower::Layer` that answers the reference engine's `cloud_provider`
//! check (`guard_core/core/checks/implementations/cloud_provider.py`), over
//! the selector parser and range table
//! [`guard_core_engine::cloud_provider`]:
//!
//! ```text
//! whitelisted || exempt (the IpGateDecision extension): pass through
//! no client IP:                                         pass through
//! no block_cloud_providers selectors:                   pass through
//! address inside a selected provider's ranges
//!   (region carve-outs honored):                        403 "Cloud provider IP not allowed"
//! everything else:                                      pass through
//! ```
//!
//! ## Reference contract, point by point
//!
//! - **Skip state**: the check returns early for
//!   `is_whitelisted || is_exempt`, read the way the global IP gate leaves
//!   it: an [`IpGateDecision`] request extension. It runs after the
//!   reference pipeline's `ip_security` stage (which sets that state) and
//!   before `user_agent`.
//! - **No client IP passes**: `if not client_ip: return None`.
//! - **Selectors**: the config is the reference `block_cloud_providers`
//!   list - bare names and `":!region"` carve-outs, validated fail-closed
//!   at construction (an unknown provider is a config error, the reference
//!   pydantic `ValueError`). An empty list is the stage's inert default
//!   (the reference `get_cloud_providers_to_check` returning nothing).
//! - **The block shape**: `403 "Cloud provider IP not allowed"`; the
//!   [`CloudIpTable::provider_details`] pair rides the answer for adapters
//!   that log (the reference logs and emits `EVENT_CLOUD_BLOCKED`
//!   events there).
//! - **Not mirrored**: the reference route-level override
//!   (`RouteConfig.block_cloud_providers` plus the `clouds` bypass check;
//!   no route system exists yet, so the stage blocks on the global
//!   selector list only), and the range fetching/refreshing itself (the
//!   reference `cloud_handler` background fetchers, its Redis caching, and
//!   `cloud_ip_refresh_interval`): ranges are fed by the adapter through
//!   the shared [`CloudIpTable`].
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::cloud_provider::{parse_cloud_selectors, CloudIpTable};
//! use guard_core_rs::cloud_provider::{CloudProviderStage, CloudProviderStageConfig};
//!
//! let table = CloudIpTable::default();
//! table
//!     .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
//!     .expect("valid ranges");
//! let stage = CloudProviderStage::new(CloudProviderStageConfig {
//!     block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
//!     table,
//!     passive_mode: false,
//! });
//!
//! let decision = stage.decide(
//!     Some(IpAddr::from_str("203.0.113.9").unwrap()),
//!     None,
//! );
//! assert_eq!(
//!     decision.expect("blocked").answer.body,
//!     "Cloud provider IP not allowed"
//! );
//!
//! // No client IP, no decision: the reference passes it.
//! assert!(stage.decide(None, None).is_none());
//! ```

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Extensions, HeaderMap, Request, Response, StatusCode};

use crate::tower::{ExtractIp, IpGateDecision, StageResponse, default_extract_ip};
pub use guard_core_engine::cloud_provider::{
    CloudConfigError, CloudIpTable, CloudRangeError, CloudSelectors, VALID_CLOUD_PROVIDERS,
    parse_cloud_selectors,
};

/// The blocked answer body (`CloudProviderCheck`'s default message).
pub const CLOUD_PROVIDER_BLOCKED_BODY: &str = "Cloud provider IP not allowed";

/// The stage's block answer: the family shape plus the
/// `(provider, network)` details pair for adapters that log (the reference
/// logs and emits `EVENT_CLOUD_BLOCKED` events with them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudDecision {
    /// The block answer (403, the default body).
    pub answer: StageResponse,
    /// The reference `get_cloud_provider_details` pair.
    pub details: Option<(String, String)>,
}

/// The stage's knobs: the parsed `block_cloud_providers` selectors and the
/// range table they consult.
#[derive(Debug, Clone, Default)]
pub struct CloudProviderStageConfig {
    /// The parsed `block_cloud_providers` selectors. The default (empty)
    /// never blocks - the reference `applies_to` registers the check only
    /// when the config or a route names providers.
    pub block_cloud_providers: CloudSelectors,
    /// The provider ranges the stage consults. Feed it with
    /// [`CloudIpTable::set_provider_ranges`] (at startup, and from a
    /// background refresher through a shared clone).
    pub table: CloudIpTable,
    /// The reference `SecurityConfig.passive_mode` (`false` by default):
    /// a cloud-provider match logs only - no `403` answer, the reference
    /// `CloudProviderCheck`'s passive path.
    pub passive_mode: bool,
}

/// The cloud-provider blocking stage over one table and one selector list.
///
/// Build it once at startup with [`CloudProviderStage::new`] (fail closed
/// on invalid selectors) and install it with [`CloudProviderStageLayer`].
/// The stage is cheaply clonable; clones share the table.
#[derive(Clone)]
pub struct CloudProviderStage {
    config: CloudProviderStageConfig,
    extract_ip: ExtractIp,
    event_sink: Option<crate::stage_events::StageEventSink>,
}

impl fmt::Debug for CloudProviderStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudProviderStage")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CloudProviderStage {
    /// Build the stage with the default IP extraction. Infallible by
    /// construction: [`CloudSelectors`] is parsed and validated by
    /// [`parse_cloud_selectors`], so an invalid provider name cannot reach
    /// the stage.
    #[must_use]
    pub fn new(config: CloudProviderStageConfig) -> Self {
        Self {
            config,
            extract_ip: Arc::new(default_extract_ip),
            event_sink: None,
        }
    }

    /// Open the builder: the IP extraction is the optional seam over
    /// [`CloudProviderStage::new`]'s default.
    pub const fn builder(config: CloudProviderStageConfig) -> CloudProviderStageBuilder {
        CloudProviderStageBuilder {
            config,
            extract_ip: None,
            event_sink: None,
        }
    }

    /// The validated config the stage decides under.
    #[must_use]
    pub const fn config(&self) -> &CloudProviderStageConfig {
        &self.config
    }

    /// One pass of the stage: `ip` is the extracted client identity
    /// (`None` passes, the reference `if not client_ip`), `gate` the
    /// global IP gate's skip state. `None` passes; `Some` carries the
    /// block answer and the `(provider, network)` details pair.
    #[must_use]
    pub fn decide(
        &self,
        ip: Option<IpAddr>,
        gate: Option<IpGateDecision>,
    ) -> Option<CloudDecision> {
        if gate.is_some_and(|gate| gate.is_whitelisted || gate.is_exempt) {
            return None;
        }
        let ip = ip?;
        if self.config.block_cloud_providers.blocked.is_empty() {
            return None;
        }
        if !self
            .config
            .table
            .is_cloud_ip(ip, &self.config.block_cloud_providers)
        {
            return None;
        }
        let details = self
            .config
            .table
            .provider_details(ip, &self.config.block_cloud_providers);
        if let Some(sink) = &self.event_sink {
            let (provider, network) = details
                .as_ref()
                .map_or((None, None), |(provider, network)| {
                    (Some(provider.as_str()), Some(network.as_str()))
                });
            crate::stage_events::emit_cloud_block(
                sink,
                provider,
                network,
                &ip.to_string(),
                self.config.passive_mode,
            );
        }
        if self.config.passive_mode {
            // Log-only: the reference's passive path emits the block events
            // and returns None.
            return None;
        }
        Some(CloudDecision {
            answer: StageResponse {
                status: StatusCode::FORBIDDEN,
                body: CLOUD_PROVIDER_BLOCKED_BODY,
                retry_after: None,
                custom_body: None,
            },
            details,
        })
    }

    /// The reference `get_cloud_providers_to_check` route lane: the
    /// route's `block_cloud_providers` selectors replace the global
    /// config's for this request (the route list overrides the global
    /// one), everything else - the whitelist/exempt skip, the table
    /// lookups, the emissions, the passive reading, and the `403`
    /// blocked shape - runs exactly like [`Self::decide`]. `None`
    /// selectors fall back to the global config (the reference's global
    /// fallback when the route names none).
    #[must_use]
    pub fn decide_route(
        &self,
        ip: Option<IpAddr>,
        gate: Option<IpGateDecision>,
        route_selectors: &CloudSelectors,
    ) -> Option<CloudDecision> {
        if gate.is_some_and(|gate| gate.is_whitelisted || gate.is_exempt) {
            return None;
        }
        let ip = ip?;
        let selectors = if route_selectors.blocked.is_empty() {
            &self.config.block_cloud_providers
        } else {
            route_selectors
        };
        if selectors.blocked.is_empty() {
            return None;
        }
        if !self.config.table.is_cloud_ip(ip, selectors) {
            return None;
        }
        let details = self.config.table.provider_details(ip, selectors);
        if let Some(sink) = &self.event_sink {
            let (provider, network) = details
                .as_ref()
                .map_or((None, None), |(provider, network)| {
                    (Some(provider.as_str()), Some(network.as_str()))
                });
            crate::stage_events::emit_cloud_block(
                sink,
                provider,
                network,
                &ip.to_string(),
                self.config.passive_mode,
            );
        }
        if self.config.passive_mode {
            return None;
        }
        Some(CloudDecision {
            answer: StageResponse {
                status: StatusCode::FORBIDDEN,
                body: CLOUD_PROVIDER_BLOCKED_BODY,
                retry_after: None,
                custom_body: None,
            },
            details,
        })
    }
}

/// The builder for [`CloudProviderStage`].
#[must_use]
pub struct CloudProviderStageBuilder {
    config: CloudProviderStageConfig,
    extract_ip: Option<ExtractIp>,
    event_sink: Option<crate::stage_events::StageEventSink>,
}

impl CloudProviderStageBuilder {
    /// Replace the default client IP extraction ([`default_extract_ip`]).
    pub fn ip_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&HeaderMap, &Extensions) -> Option<IpAddr> + Send + Sync + 'static,
    {
        self.extract_ip = Some(Arc::new(extractor));
        self
    }

    /// Install the stage event sink (the `cloud_blocked` event and the
    /// `cloud_provider` block payload).
    pub fn event_sink(mut self, sink: crate::stage_events::StageEventSink) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Build the stage.
    #[must_use]
    pub fn build(self) -> CloudProviderStage {
        let mut stage = CloudProviderStage::new(self.config);
        if let Some(extract_ip) = self.extract_ip {
            stage.extract_ip = extract_ip;
        }
        stage.event_sink = self.event_sink;
        stage
    }
}

/// The `tower::Layer` carrying [`CloudProviderStage`].
///
/// Wrap any `Service<http::Request<B>>` whose responses are
/// `http::Response<ResBody>` with `ResBody: From<&'static str>` and the
/// stage answers the reference's 403 shape itself.
#[derive(Clone)]
pub struct CloudProviderStageLayer {
    stage: CloudProviderStage,
}

impl CloudProviderStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: CloudProviderStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for CloudProviderStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudProviderStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for CloudProviderStageLayer {
    type Service = CloudProviderStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CloudProviderStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct CloudProviderStageService<S> {
    inner: S,
    stage: CloudProviderStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for CloudProviderStageService<S>
where
    S: ::tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: From<&'static str> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let ip = (self.stage.extract_ip)(request.headers(), request.extensions());
        let gate = request.extensions().get::<IpGateDecision>().copied();
        if let Some(decision) = self.stage.decide(ip, gate) {
            let response = render(&decision.answer);
            return Box::pin(async move { Ok(response) });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

/// Render the stage's block answer into the wrapped service's response body
/// type.
fn render<ResBody: From<&'static str>>(answer: &StageResponse) -> Response<ResBody> {
    let mut response = Response::new(ResBody::from(answer.body));
    *response.status_mut() = answer.status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::EVENT_CLOUD_BLOCKED;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ::tower::{Service, ServiceBuilder};

    fn aws_stage() -> CloudProviderStage {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        CloudProviderStage::new(CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
            table,
            passive_mode: false,
        })
    }

    fn passive_aws_stage() -> CloudProviderStage {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        CloudProviderStage::new(CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
            table,
            passive_mode: true,
        })
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    #[test]
    fn the_route_lane_overrides_the_global_selectors() {
        // The global stage blocks AWS only; the route's GCP list replaces
        // it for the request (the reference
        // `get_cloud_providers_to_check`: the route list overrides the
        // global one), and a route with no list falls back to the global
        // config.
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        table
            .set_provider_ranges("GCP", vec![("192.0.2.0/24".to_owned(), None)])
            .expect("valid ranges");
        let stage = CloudProviderStage::new(CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
            table,
            passive_mode: false,
        });
        let gcp = parse_cloud_selectors(["GCP"]).expect("valid selectors");

        // The route's list decides: an AWS address inside the GLOBAL list
        // passes, a GCP address outside it blocks.
        assert!(
            stage
                .decide_route(Some(ip("203.0.113.9")), None, &gcp)
                .is_none(),
            "the global AWS list no longer applies on the route"
        );
        let decision = stage
            .decide_route(Some(ip("192.0.2.9")), None, &gcp)
            .expect("blocked");
        assert_eq!(decision.answer.status, StatusCode::FORBIDDEN);
        assert_eq!(
            decision.details,
            Some(("GCP".to_owned(), "192.0.2.0/24".to_owned()))
        );

        // An empty route list falls back to the global config.
        let empty = parse_cloud_selectors([] as [&str; 0]).expect("valid selectors");
        assert!(
            stage
                .decide_route(Some(ip("203.0.113.9")), None, &empty)
                .is_some(),
            "the global list applies when the route names none"
        );

        // The global lane stays untouched.
        assert!(
            stage
                .decide_route(
                    Some(ip("192.0.2.9")),
                    None,
                    &stage.config().block_cloud_providers
                )
                .is_none(),
            "the route selector wins over the global list"
        );
    }

    #[test]
    fn the_route_lane_falls_back_through_the_empty_global_list() {
        // The global config names no providers and neither does the
        // route: the empty-selectors return answers before any lookup.
        let stage = CloudProviderStage::new(CloudProviderStageConfig::default());
        let empty = parse_cloud_selectors([] as [&str; 0]).expect("valid selectors");
        assert!(
            stage
                .decide_route(Some(ip("203.0.113.9")), None, &empty)
                .is_none()
        );
    }

    #[test]
    fn the_route_lane_emits_the_cloud_blocked_event_through_the_sink() {
        // With a bus installed the route lane emits exactly what the
        // global lane emits: the `cloud_blocked` event carrying the
        // provider and network.
        use std::sync::Mutex;

        use crate::events::SecurityEventBus;
        use crate::redact::SensitiveNames;
        use crate::stage_events::StageEventSink;

        let table = CloudIpTable::default();
        table
            .set_provider_ranges("GCP", vec![("192.0.2.0/24".to_owned(), None)])
            .expect("valid ranges");
        let seen: std::sync::Arc<Mutex<Vec<crate::events::SecurityEvent>>> =
            std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink_log = std::sync::Arc::clone(&seen);
        let bus = std::sync::Arc::new(SecurityEventBus::new(true).on_event(std::sync::Arc::new(
            move |event: &crate::events::SecurityEvent| {
                sink_log.lock().expect("sink").push(event.clone());
            },
        )));
        let sink = StageEventSink::new(None, Some(bus), SensitiveNames::default());
        let stage = CloudProviderStage::builder(CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
            table,
            passive_mode: false,
        })
        .event_sink(sink)
        .build();
        let gcp = parse_cloud_selectors(["GCP"]).expect("valid selectors");
        let decision = stage
            .decide_route(Some(ip("192.0.2.9")), None, &gcp)
            .expect("blocked");
        assert_eq!(
            decision.details,
            Some(("GCP".to_owned(), "192.0.2.0/24".to_owned()))
        );
        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EVENT_CLOUD_BLOCKED);
        assert_eq!(events[0].metadata["cloud_provider"], "GCP");
    }

    #[test]
    fn the_route_lane_skips_and_reads_passive_like_the_global_lane() {
        // The whitelist/exempt skip and the passive reading carry over.
        let stage = passive_aws_stage();
        let aws = parse_cloud_selectors(["AWS"]).expect("valid selectors");
        assert!(
            stage
                .decide_route(Some(ip("203.0.113.9")), None, &aws)
                .is_none(),
            "passive mode observes only"
        );
        let whitelisted = guard_core_engine::ip_gate::IpGateDecision {
            is_whitelisted: true,
            is_exempt: false,
        };
        assert!(
            stage
                .decide_route(Some(ip("203.0.113.9")), Some(whitelisted), &aws)
                .is_none(),
            "the whitelist skip carries over"
        );
    }

    #[test]
    fn default_stage_passes_everything_through() {
        let stage = CloudProviderStage::new(CloudProviderStageConfig::default());
        assert!(stage.config().block_cloud_providers.blocked.is_empty());
        for address in ["203.0.113.9", "192.0.2.1", "2001:db8::1"] {
            assert!(
                stage.decide(Some(ip(address)), None).is_none(),
                "an empty selector list must pass {address}"
            );
        }
    }

    #[test]
    fn blocked_provider_answers_the_reference_403_shape_with_details() {
        let stage = aws_stage();
        let decision = stage
            .decide(Some(ip("203.0.113.9")), None)
            .expect("blocked");
        assert_eq!(decision.answer.status, StatusCode::FORBIDDEN);
        assert_eq!(decision.answer.body, CLOUD_PROVIDER_BLOCKED_BODY);
        assert_eq!(decision.answer.retry_after, None);
        assert_eq!(
            decision.details,
            Some(("AWS".to_owned(), "203.0.113.0/24".to_owned()))
        );
        assert!(stage.decide(Some(ip("203.0.114.9")), None).is_none());
    }

    #[test]
    fn passive_mode_answers_nothing_for_a_cloud_match() {
        let stage = passive_aws_stage();
        assert!(stage.decide(Some(ip("203.0.113.9")), None).is_none());
    }

    #[test]
    fn missing_client_ip_passes() {
        let stage = aws_stage();
        assert!(stage.decide(None, None).is_none());
    }

    #[test]
    fn whitelisted_and_exempt_ips_skip_the_check() {
        let stage = aws_stage();
        for gate in [
            IpGateDecision {
                is_whitelisted: true,
                is_exempt: false,
            },
            IpGateDecision {
                is_whitelisted: false,
                is_exempt: true,
            },
        ] {
            assert!(
                stage.decide(Some(ip("203.0.113.9")), Some(gate)).is_none(),
                "the skip state must pass a cloud-provider address"
            );
        }
    }

    #[test]
    fn carve_outs_honor_the_region_data_through_the_stage() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges(
                "GCP",
                vec![
                    ("198.51.100.0/24".to_owned(), Some("us-central1".to_owned())),
                    (
                        "198.51.101.0/24".to_owned(),
                        Some("europe-west1".to_owned()),
                    ),
                ],
            )
            .expect("valid ranges");
        let stage = CloudProviderStage::new(CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["GCP:!us-central1"])
                .expect("valid selectors"),
            table,
            passive_mode: false,
        });
        assert!(stage.decide(Some(ip("198.51.100.9")), None).is_none());
        assert!(stage.decide(Some(ip("198.51.101.9")), None).is_some());
    }

    #[test]
    fn builder_swaps_the_ip_extractor() {
        let stage = CloudProviderStage::builder(CloudProviderStageConfig::default())
            .ip_extractor(|_headers, _extensions| Some(ip("192.0.2.99")))
            .build();
        let request = Request::builder().body(()).expect("request");
        assert_eq!(
            (stage.extract_ip)(request.headers(), request.extensions()),
            Some(ip("192.0.2.99"))
        );
    }

    /// The future the plumbing tests drive: the stub futures are always
    /// immediately ready, so a noop-waker spin never spins.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::hint::spin_loop(),
            }
        }
    }

    /// The inner service the plumbing tests wrap: counts its calls and
    /// answers `200 "inner"`.
    #[derive(Clone)]
    struct Inner {
        calls: Arc<AtomicUsize>,
    }

    impl Inner {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ::tower::Service<Request<&'static str>> for Inner {
        type Response = Response<&'static str>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<&'static str>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            drop(request);
            Box::pin(async move { Ok(Response::new("inner")) })
        }
    }

    fn request_from_client(ip_text: &str) -> Request<&'static str> {
        let socket = SocketAddr::from_str(&format!("{ip_text}:65535")).expect("socket");
        Request::builder()
            .extension(socket)
            .body("body")
            .expect("request")
    }

    #[test]
    fn layer_passes_through_and_the_inner_service_answers() {
        let layer = CloudProviderStageLayer::new(aws_stage());
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_from_client("192.0.2.20"))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
        assert_eq!(inner.call_count(), 1);
    }

    #[test]
    fn layer_answers_the_blocked_shape_without_hitting_the_inner_service() {
        let layer = CloudProviderStageLayer::new(aws_stage());
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_from_client("203.0.113.9"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.body(), &CLOUD_PROVIDER_BLOCKED_BODY);
        assert_eq!(inner.call_count(), 0, "the blocked request never hits it");
    }

    #[test]
    fn layer_clone_shares_the_stage_table() {
        let stage = aws_stage();
        let mut first = CloudProviderStageService {
            inner: Inner::new(),
            stage: stage.clone(),
        };
        let mut second = CloudProviderStageService {
            inner: Inner::new(),
            stage,
        };

        let response = block_on(first.call(request_from_client("203.0.113.9"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = block_on(second.call(request_from_client("203.0.113.9"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn stage_and_layer_debug_render_their_names() {
        let config = CloudProviderStageConfig::default();
        let stage = CloudProviderStage::new(config);
        assert!(format!("{stage:?}").contains("CloudProviderStage"));
        let layer = CloudProviderStageLayer::new(stage);
        assert!(format!("{layer:?}").contains("CloudProviderStageLayer"));
    }

    #[test]
    fn block_on_drives_a_pending_once_future() {
        struct PendingOnce {
            polled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        impl Future for PendingOnce {
            type Output = ();
            fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if !self.polled.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(())
            }
        }
        let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        block_on(PendingOnce {
            polled: std::sync::Arc::clone(&polled),
        });
    }

    #[test]
    fn the_layer_service_polls_ready() {
        let layer = CloudProviderStageLayer::new(CloudProviderStage::new(
            CloudProviderStageConfig::default(),
        ));
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(Inner::new());
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let polled = ::tower::Service::<Request<&'static str>>::poll_ready(&mut service, &mut cx);
        assert!(polled.is_ready());
        assert_eq!(polled.map(|result| result.is_ok()), Poll::Ready(true));
    }

    #[test]
    fn a_cloud_match_fires_the_cloud_blocked_event_through_the_sink() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_log = Arc::clone(&log);
        let bus = Arc::new(
            crate::events::SecurityEventBus::new(true).on_event(Arc::new(
                move |event: &crate::events::SecurityEvent| {
                    sink_log.lock().expect("log").push(event.clone());
                },
            )),
        );
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        let stage = CloudProviderStage::builder(CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
            table,
            passive_mode: false,
        })
        .event_sink(crate::stage_events::StageEventSink::new(
            None,
            Some(bus),
            crate::redact::SensitiveNames::default(),
        ))
        .build();

        let decision = stage
            .decide(Some(ip("203.0.113.9")), None)
            .expect("blocked");
        assert_eq!(decision.answer.status, StatusCode::FORBIDDEN);
        let events = log.lock().expect("log").clone();
        assert_eq!(events.len(), 1, "the cloud_blocked event rode the bus");
        assert_eq!(events[0].event_type, EVENT_CLOUD_BLOCKED);
        assert_eq!(events[0].action_taken, "request_blocked");
        assert_eq!(events[0].metadata["cloud_provider"], "AWS");
        assert_eq!(events[0].metadata["network"], "203.0.113.0/24");
    }
}
