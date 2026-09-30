//! The geo country blocking pipeline stage for tower stacks.
//!
//! One `tower::Layer` that answers the reference engine's global country
//! check - the country branch of `check_ip_access`
//! (`guard_core/_utils/access_control.py`), which the reference pipeline
//! runs inside its `ip_security` stage - over the decision core
//! [`guard_core_engine::geo`]:
//!
//! ```text
//! a global whitelist match (the IpGateDecision is_whitelisted): pass
//! geolocation unavailable (no handler verdict):
//!     blocked iff whitelist_countries is non-empty     403 "Forbidden"
//! country in blocked_countries:                        403 "Forbidden"
//! whitelist_countries non-empty and country unlisted:  403 "Forbidden"
//! everything else (loopback included):                 pass through
//! ```
//!
//! ## Reference contract, point by point
//!
//! - **The skip flag is the whitelist flag only**: the reference sets
//!   `skip_countries` for a global `whitelist` match
//!   (`IpGateDecision::is_whitelisted`); `exempt_ips` does **not** skip
//!   the country check (exemption is rate-limit/user-agent/cloud noise
//!   reduction, never country immunity). A missing extension means
//!   neither flag is set.
//! - **The block shape** is the reference `_check_global_ip_restrictions`
//!   answer: `403 "Forbidden"`; the [`CountryBlock::reason`]
//!   (`"IP from blocked country: {code}"`, or the generic list reason)
//!   rides the decision for adapters that log.
//! - **Config**: the country codes are uppercased at parse time
//!   (`_validate_country_set_value`) and compared exactly against the
//!   handler's verdict; the loopback exemption runs before geolocation;
//!   an unresolved address blocks only under a restrictive whitelist.
//! - **No client IP** mirrors the reference's
//!   `_check_unknown_identity_access`: an unidentifiable client is blocked
//!   when `whitelist_countries` is non-empty (a restrictive whitelist is
//!   restrictive) and passes otherwise. Note the reference distinguishes a
//!   missing client (the `ip_security` check skips entirely) from the
//!   `UNKNOWN_CLIENT_IDENTITY` sentinel (list checks apply); the Rust
//!   family has one representation for both, and this stage takes the
//!   fail-closed reading for restrictive whitelists.
//! - **Not mirrored**: the reference's per-route country rules
//!   (`RouteConfig.blocked_countries` / `whitelist_countries` via
//!   `check_country_access` - no route system yet, so this stage is the
//!   global rules only), the `log_country_check_level` verdict logging and
//!   the `EVENT_IP_BLOCKED` emission, and the geolocation itself (the
//!   reference reads an `IPInfo` `MMDB`; the adapter supplies the
//!   [`GeoIpHandler`] verdicts).
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//! use std::sync::Arc;
//!
//! use guard_core_engine::geo::{parse_country_lists, GeoIpHandler};
//! use guard_core_rs::geo::{GeoStage, GeoStageConfig};
//!
//! struct Germany;
//! impl GeoIpHandler for Germany {
//!     fn get_country(&self, _ip: IpAddr) -> Option<String> {
//!         Some("DE".to_owned())
//!     }
//! }
//!
//! let stage = GeoStage::new(GeoStageConfig {
//!     gate: parse_country_lists([] as [&str; 0], ["RU"]),
//!     handler: Some(Arc::new(Germany)),
//!     passive_mode: false,
//! });
//!
//! let decision = stage.decide(Some(IpAddr::from_str("192.0.2.1").unwrap()), None);
//! assert!(decision.is_none(), "DE is not blocklisted");
//! ```
//!
//! Under a blocklisting gate a DE address passes; swap the handler for one
//! resolving `RU` and the same request is answered `403 "Forbidden"`.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Extensions, HeaderMap, Request, Response, StatusCode};

use crate::tower::{ExtractIp, IpGateDecision, StageResponse, default_extract_ip};
pub use guard_core_engine::geo::{
    CountryBlock, CountryGate, GeoIpHandler, check_countries, generic_list_block_reason,
    generic_list_block_reason_for, parse_country_lists,
};

/// The blocked answer body (the reference `_check_global_ip_restrictions`
/// default message for a global IP denial).
pub const FORBIDDEN_BODY: &str = "Forbidden";

/// The identity the reference uses when extraction fails
/// (`UNKNOWN_CLIENT_IDENTITY`): the string the generic list reason carries
/// for a request without a client IP.
pub const UNKNOWN_CLIENT_IP: &str = "unknown";

/// The stage's knobs: the parsed country rules and the geolocation seam.
#[derive(Clone, Default)]
pub struct GeoStageConfig {
    /// The parsed `whitelist_countries` / `blocked_countries` rules.
    pub gate: CountryGate,
    /// The geolocation seam. The default (no handler) resolves nothing, so
    /// a restrictive whitelist blocks everything and a blocklist never
    /// fires - configure a handler for either rule to mean anything.
    pub handler: Option<Arc<dyn GeoIpHandler>>,
    /// The reference `SecurityConfig.passive_mode` (`false` by default):
    /// a country match logs only - no `403` answer, the reference
    /// ip-security geo path's passive behavior.
    pub passive_mode: bool,
}

impl fmt::Debug for GeoStageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeoStageConfig")
            .field("gate", &self.gate)
            .field("handler", &self.handler.is_some())
            .field("passive_mode", &self.passive_mode)
            .finish()
    }
}

/// The stage's block answer: the family shape plus the reference
/// `IpAccessResult` reason and resolved country.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDecision {
    /// The block answer (403, the "Forbidden" body).
    pub answer: StageResponse,
    /// The resolved country and the reference reason.
    pub block: CountryBlock,
}

/// The geo country blocking stage over one country gate and one handler.
///
/// Build it once at startup with [`GeoStage::new`] and install it with
/// [`GeoStageLayer`]. The stage is cheaply clonable.
#[derive(Clone)]
pub struct GeoStage {
    config: GeoStageConfig,
    extract_ip: ExtractIp,
    event_sink: Option<crate::stage_events::StageEventSink>,
}

impl fmt::Debug for GeoStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeoStage")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GeoStage {
    /// Build the stage with the default IP extraction.
    #[must_use]
    pub fn new(config: GeoStageConfig) -> Self {
        Self {
            config,
            extract_ip: Arc::new(default_extract_ip),
            event_sink: None,
        }
    }

    /// Open the builder: the IP extraction is the optional seam over
    /// [`GeoStage::new`]'s default.
    pub const fn builder(config: GeoStageConfig) -> GeoStageBuilder {
        GeoStageBuilder {
            config,
            extract_ip: None,
            event_sink: None,
        }
    }

    /// The validated config the stage decides under.
    #[must_use]
    pub const fn config(&self) -> &GeoStageConfig {
        &self.config
    }

    /// One pass of the stage: `ip` is the extracted client identity and
    /// `gate` the global IP gate's skip state. `None` passes; `Some` is
    /// the block answer.
    #[must_use]
    pub fn decide(&self, ip: Option<IpAddr>, gate: Option<IpGateDecision>) -> Option<GeoDecision> {
        // The reference skip_countries flag: set by a global whitelist
        // match only, never by exemption.
        if gate.is_some_and(|gate| gate.is_whitelisted) {
            return None;
        }
        let handler = NoopHandler(self.config.handler.as_deref());
        if let Some(ip) = ip {
            let block = check_countries(ip, &self.config.gate, &handler, false)?;
            return self.answer(block, Some(ip));
        }
        // No client identity: the reference `_check_unknown_identity_access`
        // reading - a restrictive whitelist blocks the unidentifiable.
        if self.config.gate.whitelist_countries.is_empty() {
            return None;
        }
        self.answer(
            CountryBlock {
                country: None,
                // `ip` in the reference reason is the UNKNOWN_CLIENT_IDENTITY
                // sentinel string.
                reason: generic_list_block_reason_for(UNKNOWN_CLIENT_IP),
            },
            None,
        )
    }

    /// The block answer, or `None` under passive mode: the reference's
    /// passive geo path logs the country match and lets the request pass.
    fn answer(&self, block: CountryBlock, ip: Option<IpAddr>) -> Option<GeoDecision> {
        if let Some(sink) = &self.event_sink {
            let rule = if self.config.gate.whitelist_countries.is_empty() {
                crate::stage_events::CountryRule::Blacklist
            } else {
                crate::stage_events::CountryRule::Whitelist
            };
            crate::stage_events::emit_geo_block(
                sink,
                &block.reason,
                block.country.as_deref(),
                rule,
                &ip.map_or_else(String::new, |addr| addr.to_string()),
                self.config.passive_mode,
            );
        }
        if self.config.passive_mode {
            return None;
        }
        Some(Self::decision(block))
    }

    const fn decision(block: CountryBlock) -> GeoDecision {
        GeoDecision {
            answer: StageResponse {
                status: StatusCode::FORBIDDEN,
                body: FORBIDDEN_BODY,
                retry_after: None,
                custom_body: None,
            },
            block,
        }
    }
}

/// Adapts the optional handler seam to the `&dyn GeoIpHandler` the core
/// takes: without a handler nothing resolves.
struct NoopHandler<'a>(Option<&'a dyn GeoIpHandler>);

impl GeoIpHandler for NoopHandler<'_> {
    fn get_country(&self, ip: IpAddr) -> Option<String> {
        self.0.and_then(|handler| handler.get_country(ip))
    }
}

/// The builder for [`GeoStage`].
#[must_use]
pub struct GeoStageBuilder {
    config: GeoStageConfig,
    extract_ip: Option<ExtractIp>,
    event_sink: Option<crate::stage_events::StageEventSink>,
}

impl GeoStageBuilder {
    /// Replace the default client IP extraction ([`default_extract_ip`]).
    pub fn ip_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&HeaderMap, &Extensions) -> Option<IpAddr> + Send + Sync + 'static,
    {
        self.extract_ip = Some(Arc::new(extractor));
        self
    }

    /// Install the stage event sink (the `country_blocked` event and the
    /// `ip_security` block payload).
    pub fn event_sink(mut self, sink: crate::stage_events::StageEventSink) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Build the stage.
    #[must_use]
    pub fn build(self) -> GeoStage {
        let mut stage = GeoStage::new(self.config);
        if let Some(extract_ip) = self.extract_ip {
            stage.extract_ip = extract_ip;
        }
        stage.event_sink = self.event_sink;
        stage
    }
}

/// The `tower::Layer` carrying [`GeoStage`].
///
/// Wrap any `Service<http::Request<B>>` whose responses are
/// `http::Response<ResBody>` with `ResBody: From<&'static str>` and the
/// stage answers the reference's 403 shape itself.
#[derive(Clone)]
pub struct GeoStageLayer {
    stage: GeoStage,
}

impl GeoStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: GeoStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for GeoStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeoStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for GeoStageLayer {
    type Service = GeoStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GeoStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct GeoStageService<S> {
    inner: S,
    stage: GeoStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for GeoStageService<S>
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
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ::tower::{Service, ServiceBuilder};

    /// A handler resolving every address to a fixed country.
    struct Fixed(&'static str);

    impl GeoIpHandler for Fixed {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some(self.0.to_owned())
        }
    }

    /// A handler backed by a table (per-address verdicts).
    struct Table(HashMap<String, &'static str>);

    impl GeoIpHandler for Table {
        fn get_country(&self, ip: IpAddr) -> Option<String> {
            self.0.get(&ip.to_string()).map(|code| (*code).to_owned())
        }
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    fn blocklist_stage() -> GeoStage {
        GeoStage::new(GeoStageConfig {
            gate: parse_country_lists([] as [&str; 0], ["RU"]),
            handler: Some(Arc::new(Table(HashMap::from([
                ("192.0.2.1".to_owned(), "RU"),
                ("192.0.2.2".to_owned(), "DE"),
            ])))),
            passive_mode: false,
        })
    }

    fn whitelist_stage() -> GeoStage {
        GeoStage::new(GeoStageConfig {
            gate: parse_country_lists(["US"], [] as [&str; 0]),
            handler: Some(Arc::new(Fixed("DE"))),
            passive_mode: false,
        })
    }

    #[test]
    fn blocklist_blocks_only_the_listed_country() {
        let stage = blocklist_stage();
        let decision = stage.decide(Some(ip("192.0.2.1")), None).expect("blocked");
        assert_eq!(decision.answer.status, StatusCode::FORBIDDEN);
        assert_eq!(decision.answer.body, FORBIDDEN_BODY);
        assert_eq!(decision.block.country.as_deref(), Some("RU"));
        assert_eq!(decision.block.reason, "IP from blocked country: RU");
        assert!(stage.decide(Some(ip("192.0.2.2")), None).is_none());
        // An unresolvable address passes a blocklist-only gate.
        assert!(stage.decide(Some(ip("192.0.2.3")), None).is_none());
    }

    #[test]
    fn whitelist_blocks_the_unlisted_and_the_unresolved() {
        let stage = whitelist_stage();
        let decision = stage.decide(Some(ip("192.0.2.1")), None).expect("blocked");
        assert_eq!(decision.block.reason, "IP from blocked country: DE");
        // Loopback passes before geolocation, even a restrictive one.
        assert!(stage.decide(Some(ip("127.0.0.1")), None).is_none());
        assert!(stage.decide(Some(ip("::1")), None).is_none());

        let stage = GeoStage::new(GeoStageConfig {
            gate: parse_country_lists(["US"], [] as [&str; 0]),
            handler: None,
            passive_mode: false,
        });
        let decision = stage.decide(Some(ip("192.0.2.1")), None).expect("blocked");
        assert_eq!(
            decision.block.reason,
            "IP 192.0.2.1 not in global allowlist/blocklist"
        );
    }

    #[test]
    fn passive_mode_answers_nothing_for_a_country_match() {
        let stage = GeoStage::new(GeoStageConfig {
            gate: parse_country_lists([] as [&str; 0], ["RU"]),
            handler: Some(Arc::new(Table(HashMap::from([(
                "192.0.2.1".to_owned(),
                "RU",
            )])))),
            passive_mode: true,
        });
        // Both the resolved-country block and the unknown-identity
        // whitelist block pass through under passive mode.
        assert!(stage.decide(Some(ip("192.0.2.1")), None).is_none());
        let whitelist = GeoStage::new(GeoStageConfig {
            gate: parse_country_lists(["US"], [] as [&str; 0]),
            handler: None,
            passive_mode: true,
        });
        assert!(whitelist.decide(None, None).is_none());
    }

    #[test]
    fn a_whitelist_match_skips_but_exemption_does_not() {
        let stage = blocklist_stage();
        // The whitelist flag skips the country check entirely.
        assert!(
            stage
                .decide(
                    Some(ip("192.0.2.1")),
                    Some(IpGateDecision {
                        is_whitelisted: true,
                        is_exempt: false
                    })
                )
                .is_none(),
            "a whitelist match skips the country rules"
        );
        // Exemption does not: the blocked country still answers.
        let decision = stage
            .decide(
                Some(ip("192.0.2.1")),
                Some(IpGateDecision {
                    is_whitelisted: false,
                    is_exempt: true,
                }),
            )
            .expect("exempt but blocklisted");
        assert_eq!(decision.answer.body, FORBIDDEN_BODY);
    }

    #[test]
    fn a_missing_client_identity_blocks_only_under_a_whitelist() {
        let stage = blocklist_stage();
        assert!(stage.decide(None, None).is_none());

        let stage = whitelist_stage();
        let decision = stage.decide(None, None).expect("restrictive whitelist");
        assert_eq!(decision.block.country, None);
        assert_eq!(decision.answer.body, FORBIDDEN_BODY);
    }

    #[test]
    fn default_config_passes_everything() {
        let stage = GeoStage::new(GeoStageConfig::default());
        assert!(stage.config().gate.whitelist_countries.is_empty());
        for address in ["192.0.2.1", "127.0.0.1", "2001:db8::1"] {
            assert!(stage.decide(Some(ip(address)), None).is_none());
        }
        assert!(stage.decide(None, None).is_none());
    }

    #[test]
    fn builder_swaps_the_ip_extractor() {
        let stage = GeoStage::builder(GeoStageConfig::default())
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
        let layer = GeoStageLayer::new(blocklist_stage());
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_from_client("192.0.2.2"))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
        assert_eq!(inner.call_count(), 1);
    }

    #[test]
    fn layer_answers_the_forbidden_shape_without_hitting_the_inner_service() {
        let layer = GeoStageLayer::new(blocklist_stage());
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_from_client("192.0.2.1"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.body(), &FORBIDDEN_BODY);
        assert_eq!(inner.call_count(), 0, "the blocked request never hits it");
    }

    #[test]
    fn layer_clone_shares_the_stage_config() {
        let stage = blocklist_stage();
        let mut first = GeoStageService {
            inner: Inner::new(),
            stage: stage.clone(),
        };
        let mut second = GeoStageService {
            inner: Inner::new(),
            stage,
        };

        let response = block_on(first.call(request_from_client("192.0.2.1"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = block_on(second.call(request_from_client("192.0.2.1"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
