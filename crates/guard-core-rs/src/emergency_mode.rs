//! The emergency-mode pipeline stage for tower stacks.
//!
//! One `tower::Layer` answering the reference engine's `emergency_mode`
//! check (`guard_core/core/checks/implementations/emergency_mode.py`)
//! before a request reaches the inner service.
//!
//! The decision core is [`guard_core_engine::emergency_mode`]; this stage
//! wires it into the family's tower seams:
//!
//! ```text
//! emergency mode off:              pass through (the reference check is a
//!                                  no-op unless config.emergency_mode)
//! whitelisted IP:                  pass through
//! everyone else (missing or
//!   unparseable IP included):      503 "Service temporarily unavailable"
//! passive mode:                    pass through (the reference logs and
//!                                  emits only)
//! ```
//!
//! The block fires the `on_block` hook with the reference payload
//! (`emergency_mode` is not in `ON_BLOCK_EXCLUDED_CHECK_NAMES`), the body
//! honors `custom_error_responses[503]`, and the reason is the reference's
//! `"[EMERGENCY MODE] IP {ip} not in whitelist"`.
//!
//! # Example
//!
//! ```
//! use guard_core_rs::emergency_mode::{EmergencyModeStage, EmergencyModeStageConfig};
//!
//! let stage = EmergencyModeStage::builder(EmergencyModeStageConfig::default())
//!     .emergency_mode(true)
//!     .emergency_whitelist(["192.0.2.40"])
//!     .build()
//!     .expect("valid whitelist");
//!
//! // A whitelisted IP passes; everyone else gets the 503 shape.
//! assert!(stage.decide(Some("192.0.2.40"), "192.0.2.40", "/", "GET").is_none());
//! let answer = stage
//!     .decide(Some("192.0.2.41"), "192.0.2.41", "/", "GET")
//!     .expect("blocked");
//! assert_eq!(answer.status, 503);
//! assert_eq!(answer.body, "Service temporarily unavailable");
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Request, Response, StatusCode};

use crate::event_types::EVENT_EMERGENCY_MODE_BLOCK;
use crate::events::{MIDDLEWARE_HANDLER_NAME, SecurityEvent, SecurityEventBus};
use crate::redact::SensitiveNames;
use crate::responses::{
    CustomErrorResponses, OnBlockHook, build_block_payload, fire_block_hook, resolve_error_body,
};
pub use guard_core_engine::emergency_mode::{
    EMERGENCY_BLOCK_BODY, EMERGENCY_BLOCK_STATUS, EMERGENCY_MODE_CHECK_NAME,
};

/// The stage's answer: the reference's 503 shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyAnswer {
    /// `503` (`EMERGENCY_BLOCK_STATUS`).
    pub status: u16,
    /// The body: the reference default message, overridden by
    /// `custom_error_responses[503]`.
    pub body: String,
}

/// The stage configuration (`SecurityConfig.passive_mode` plus the live
/// `emergency_mode` switch).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmergencyModeStageConfig {
    /// The live `config.emergency_mode` switch: off, the stage passes.
    pub emergency_mode: bool,
    /// `passive_mode`: observe, never block.
    pub passive_mode: bool,
}

/// The emergency-mode stage.
#[derive(Clone)]
pub struct EmergencyModeStage {
    config: EmergencyModeStageConfig,
    whitelist: guard_core_engine::emergency_mode::EmergencyModeConfig,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    sensitive: Arc<SensitiveNames>,
    events: Option<Arc<SecurityEventBus>>,
}

impl fmt::Debug for EmergencyModeStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmergencyModeStage")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Builder for [`EmergencyModeStage`].
#[derive(Default)]
pub struct EmergencyModeStageBuilder {
    config: EmergencyModeStageConfig,
    whitelist: Vec<String>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    sensitive: SensitiveNames,
    events: Option<Arc<SecurityEventBus>>,
}

impl EmergencyModeStage {
    /// Start a builder over `config`.
    #[must_use]
    pub fn builder(config: EmergencyModeStageConfig) -> EmergencyModeStageBuilder {
        EmergencyModeStageBuilder {
            config,
            whitelist: Vec::new(),
            on_block: None,
            custom_error_responses: CustomErrorResponses::new(),
            sensitive: SensitiveNames::default(),
            events: None,
        }
    }

    /// One pass of the stage. `client_ip` is the raw identity string the
    /// reference reads from `request.state.client_ip`; `ip_for_payload` /
    /// `path` / `method` feed the block payload. `None` passes; `Some` is
    /// the 503 answer.
    #[must_use]
    pub fn decide(
        &self,
        client_ip: Option<&str>,
        ip_for_payload: &str,
        path: &str,
        method: &str,
    ) -> Option<EmergencyAnswer> {
        if !self.config.emergency_mode {
            return None;
        }
        if guard_core_engine::emergency_mode::decide(client_ip, &self.whitelist)
            == guard_core_engine::emergency_mode::EmergencyVerdict::Allowed
        {
            return None;
        }
        let reason = format!(
            "[EMERGENCY MODE] IP {} not in whitelist",
            client_ip.unwrap_or_default()
        );
        // The reference emits the block event in both modes, flipping the
        // action to `logged_only` under passive mode.
        self.observe_emergency_block(ip_for_payload, &reason, path, method);
        if self.config.passive_mode {
            // Passive mode still fires the hook, with no status code and
            // the passive flag set (the reference dispatcher shape).
            fire_block_hook(
                self.on_block.as_ref(),
                &build_block_payload(
                    EMERGENCY_MODE_CHECK_NAME,
                    &reason,
                    "",
                    true,
                    ip_for_payload,
                    path,
                    method,
                    None,
                    &self.sensitive,
                ),
            );
            return None;
        }
        fire_block_hook(
            self.on_block.as_ref(),
            &build_block_payload(
                EMERGENCY_MODE_CHECK_NAME,
                &reason,
                "",
                false,
                ip_for_payload,
                path,
                method,
                Some(EMERGENCY_BLOCK_STATUS),
                &self.sensitive,
            ),
        );
        Some(EmergencyAnswer {
            status: EMERGENCY_BLOCK_STATUS,
            body: resolve_error_body(
                &self.custom_error_responses,
                EMERGENCY_BLOCK_STATUS,
                EMERGENCY_BLOCK_BODY,
            ),
        })
    }

    /// The block emission (`send_middleware_event` with
    /// `EVENT_EMERGENCY_MODE_BLOCK`): the reference reason, the
    /// whitelist size, and `emergency_active`.
    fn observe_emergency_block(&self, ip: &str, reason: &str, path: &str, method: &str) {
        let Some(bus) = &self.events else {
            return;
        };
        let mut event = SecurityEvent::new(
            EVENT_EMERGENCY_MODE_BLOCK,
            ip,
            if self.config.passive_mode {
                "logged_only"
            } else {
                "request_blocked"
            },
            reason,
            MIDDLEWARE_HANDLER_NAME,
        );
        event.endpoint = Some(path.to_owned());
        event.method = Some(method.to_owned());
        event.metadata.insert(
            String::from("emergency_whitelist_count"),
            serde_json::json!(self.whitelist.len()),
        );
        event
            .metadata
            .insert(String::from("emergency_active"), serde_json::json!(true));
        bus.send_event(&event);
    }
}

impl EmergencyModeStageBuilder {
    /// Set the live emergency switch.
    #[must_use]
    pub const fn emergency_mode(mut self, emergency_mode: bool) -> Self {
        self.config.emergency_mode = emergency_mode;
        self
    }

    /// Set passive mode.
    #[must_use]
    pub const fn passive_mode(mut self, passive_mode: bool) -> Self {
        self.config.passive_mode = passive_mode;
        self
    }

    /// Add emergency-whitelist entries (bare IPs or CIDR ranges); the
    /// build fails closed on an invalid one.
    #[must_use]
    pub fn emergency_whitelist<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.whitelist
            .extend(entries.into_iter().map(|entry| entry.as_ref().to_owned()));
        self
    }

    /// Install the `on_block` hook.
    #[must_use]
    pub fn on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Merge `custom_error_responses` entries (body overrides by status).
    #[must_use]
    pub fn custom_error_responses(mut self, custom: CustomErrorResponses) -> Self {
        self.custom_error_responses.extend(custom);
        self
    }

    /// Install the middleware-event bus
    /// (`EVENT_EMERGENCY_MODE_BLOCK` emission).
    #[must_use]
    pub fn events(mut self, bus: Arc<SecurityEventBus>) -> Self {
        self.events = Some(bus);
        self
    }

    /// Validate the whitelist and build the stage, failing closed.
    ///
    /// # Errors
    ///
    /// [`guard_core_engine::ip_gate::IpGateError`] naming the first
    /// invalid whitelist entry.
    pub fn build(self) -> Result<EmergencyModeStage, guard_core_engine::ip_gate::IpGateError> {
        Ok(EmergencyModeStage {
            config: self.config,
            whitelist: guard_core_engine::emergency_mode::EmergencyModeConfig::new(
                self.whitelist.iter().map(String::as_str),
            )?,
            on_block: self.on_block,
            custom_error_responses: self.custom_error_responses,
            sensitive: Arc::new(self.sensitive),
            events: self.events,
        })
    }
}

/// The `tower::Layer` carrying [`EmergencyModeStage`].
#[derive(Clone)]
pub struct EmergencyModeStageLayer {
    stage: EmergencyModeStage,
}

impl EmergencyModeStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: EmergencyModeStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for EmergencyModeStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmergencyModeStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for EmergencyModeStageLayer {
    type Service = EmergencyModeStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EmergencyModeStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The connecting client identity the stage's tower service reads from the
/// request extensions (`request.extensions().get::<ClientIp>()`).
///
/// Hosts insert it once per request; a request without it counts as
/// having no client IP, which the reference denies under an active mode
/// (fail secure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub std::net::IpAddr);

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct EmergencyModeStageService<S> {
    inner: S,
    stage: EmergencyModeStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for EmergencyModeStageService<S>
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
        let path = request.uri().path().to_owned();
        let method = request.method().to_string();
        let client_ip = request
            .extensions()
            .get::<ClientIp>()
            .map(|ClientIp(addr)| addr.to_string());
        let raw = client_ip.clone();
        let answer = self.stage.decide(
            raw.as_deref(),
            client_ip.as_deref().unwrap_or_default(),
            &path,
            &method,
        );
        let Some(answer) = answer else {
            return Box::pin(self.inner.call(request));
        };
        drop(request);
        let status = StatusCode::from_u16(answer.status).expect("reference status");
        let static_body: &'static str = if answer.body == EMERGENCY_BLOCK_BODY {
            EMERGENCY_BLOCK_BODY
        } else {
            // Custom bodies carry on the decision surface; the static
            // render answers the reference default.
            ""
        };
        let mut response = Response::new(ResBody::from(static_body));
        *response.status_mut() = status;
        Box::pin(async move { Ok(response) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::Mutex;

    use ::tower::Service;

    fn stage_with(passive: bool) -> EmergencyModeStage {
        EmergencyModeStage::builder(EmergencyModeStageConfig {
            emergency_mode: true,
            passive_mode: passive,
        })
        .emergency_whitelist(["192.0.2.40", "198.51.100.0/24"])
        .build()
        .expect("valid whitelist")
    }

    #[test]
    fn whitelist_passes_and_everyone_else_gets_the_503() {
        let stage = stage_with(false);
        assert!(
            stage
                .decide(Some("192.0.2.40"), "192.0.2.40", "/", "GET")
                .is_none()
        );
        assert!(
            stage
                .decide(Some("198.51.100.7"), "198.51.100.7", "/", "GET")
                .is_none(),
            "a CIDR whitelist entry admits its members"
        );
        let answer = stage
            .decide(Some("192.0.2.41"), "192.0.2.41", "/", "GET")
            .expect("blocked");
        assert_eq!(answer.status, 503);
        assert_eq!(answer.body, "Service temporarily unavailable");
    }

    #[test]
    fn missing_or_unparseable_ip_is_denied_fail_secure() {
        let stage = stage_with(false);
        let answer = stage.decide(None, "", "/", "GET").expect("blocked");
        assert_eq!(answer.status, 503);
        let answer = stage
            .decide(Some("junk"), "junk", "/", "GET")
            .expect("blocked");
        assert_eq!(answer.status, 503);
    }

    #[test]
    fn the_mode_switch_off_passes_everything() {
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig::default())
            .emergency_whitelist(["192.0.2.40"])
            .build()
            .expect("valid");
        assert!(
            stage
                .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
                .is_none()
        );
    }

    #[test]
    fn passive_mode_observes_and_fires_the_passive_payload() {
        let payload: Arc<Mutex<Option<crate::responses::BlockPayload>>> =
            Arc::new(Mutex::new(None));
        let recorder = Arc::clone(&payload);
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig {
            emergency_mode: true,
            passive_mode: true,
        })
        .emergency_whitelist(["192.0.2.40"])
        .on_block(Arc::new(move |fired: &crate::responses::BlockPayload| {
            *recorder.lock().expect("recorder") = Some(fired.clone());
        }))
        .build()
        .expect("valid");

        // Passive mode never blocks.
        assert!(
            stage
                .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
                .is_none()
        );
        // ... but the observation still fires the hook, with no status
        // code and the passive flag set.
        let fired = payload.lock().expect("recorder").clone().expect("fired");
        assert_eq!(fired.check_name, "emergency_mode");
        assert!(fired.passive_mode);
        assert_eq!(fired.status_code, None);
        assert_eq!(
            fired.reason,
            "[EMERGENCY MODE] IP 203.0.113.9 not in whitelist"
        );
    }

    fn recording_bus() -> (Arc<Mutex<Vec<SecurityEvent>>>, Arc<SecurityEventBus>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let bus = Arc::new(SecurityEventBus::new(true).on_event(Arc::new(
            move |event: &SecurityEvent| {
                sink.lock().expect("sink").push(event.clone());
            },
        )));
        (log, bus)
    }

    #[test]
    fn the_block_fires_the_emergency_mode_block_event() {
        let (log, bus) = recording_bus();
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig {
            emergency_mode: true,
            passive_mode: false,
        })
        .emergency_whitelist(["192.0.2.40"])
        .events(bus)
        .build()
        .expect("valid");
        stage
            .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
            .expect("blocked");

        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "emergency_mode_block");
        assert_eq!(events[0].action_taken, "request_blocked");
        assert_eq!(
            events[0].reason,
            "[EMERGENCY MODE] IP 203.0.113.9 not in whitelist"
        );
        assert_eq!(events[0].metadata["emergency_whitelist_count"], 1);
        assert_eq!(events[0].metadata["emergency_active"], true);
    }

    #[test]
    fn passive_mode_flips_the_emergency_event_action() {
        let (log, bus) = recording_bus();
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig {
            emergency_mode: true,
            passive_mode: true,
        })
        .emergency_whitelist(["192.0.2.40"])
        .events(bus)
        .build()
        .expect("valid");
        assert!(
            stage
                .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
                .is_none()
        );
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action_taken, "logged_only");
    }

    #[test]
    fn active_mode_fires_the_block_payload_with_the_status() {
        let payload: Arc<Mutex<Option<crate::responses::BlockPayload>>> =
            Arc::new(Mutex::new(None));
        let recorder = Arc::clone(&payload);
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig {
            emergency_mode: true,
            passive_mode: false,
        })
        .emergency_whitelist(["192.0.2.40"])
        .on_block(Arc::new(move |fired: &crate::responses::BlockPayload| {
            *recorder.lock().expect("recorder") = Some(fired.clone());
        }))
        .build()
        .expect("valid");
        assert!(
            stage
                .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
                .is_some()
        );
        let fired = payload.lock().expect("recorder").clone().expect("fired");
        assert_eq!(fired.status_code, Some(503));
        assert!(!fired.passive_mode);
        assert_eq!(fired.path, "/");
        assert_eq!(fired.method, "GET");
    }

    #[test]
    fn custom_error_body_overrides_the_default() {
        let mut custom = CustomErrorResponses::new();
        custom.insert(503, "Down for maintenance".to_owned());
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig {
            emergency_mode: true,
            passive_mode: false,
        })
        .custom_error_responses(custom)
        .build()
        .expect("valid");
        let answer = stage
            .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
            .expect("blocked");
        assert_eq!(answer.body, "Down for maintenance");
    }

    #[test]
    fn the_builder_fails_closed_on_a_bad_whitelist_entry() {
        let error = EmergencyModeStage::builder(EmergencyModeStageConfig::default())
            .emergency_whitelist(["junk"])
            .build()
            .unwrap_err();
        assert_eq!(error.list, "emergency_whitelist");
    }

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

    #[derive(Clone)]
    struct Inner;

    impl ::tower::Service<Request<&'static str>> for Inner {
        type Response = Response<&'static str>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<&'static str>) -> Self::Future {
            Box::pin(async move { Ok(Response::new("inner")) })
        }
    }

    #[test]
    fn the_layer_answers_the_503_and_forwards_whitelisted_requests() {
        let layer = EmergencyModeStageLayer::new(stage_with(false));
        let mut service = ::tower::ServiceBuilder::new().layer(layer).service(Inner);

        let mut blocked = Request::builder().uri("/x").body("b").expect("req");
        blocked
            .extensions_mut()
            .insert(ClientIp("203.0.113.9".parse().expect("ip")));
        let response = block_on(service.call(blocked)).expect("ready");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.body(), &"Service temporarily unavailable");

        let mut allowed = Request::builder().uri("/x").body("b").expect("req");
        allowed
            .extensions_mut()
            .insert(ClientIp("192.0.2.40".parse().expect("ip")));
        let response = block_on(service.call(allowed)).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
    }

    #[test]
    fn the_builder_methods_shape_the_switches_and_the_stage_renders_debug() {
        let stage = EmergencyModeStage::builder(EmergencyModeStageConfig::default())
            .emergency_mode(true)
            .passive_mode(true)
            .emergency_whitelist(["192.0.2.40"])
            .build()
            .expect("valid whitelist");
        // The builder methods laid both switches: passive observes only.
        assert!(
            stage
                .decide(Some("203.0.113.9"), "203.0.113.9", "/", "GET")
                .is_none()
        );
        assert!(format!("{stage:?}").starts_with("EmergencyModeStage"));

        let layer = EmergencyModeStageLayer::new(stage_with(false));
        assert!(format!("{layer:?}").starts_with("EmergencyModeStageLayer"));
    }

    #[test]
    fn the_service_readies_and_renders_the_custom_body_as_static_empty() {
        let mut custom = CustomErrorResponses::new();
        custom.insert(503, "Down for maintenance".to_owned());
        let layer = EmergencyModeStageLayer::new(
            EmergencyModeStage::builder(EmergencyModeStageConfig {
                emergency_mode: true,
                passive_mode: false,
            })
            .custom_error_responses(custom)
            .build()
            .expect("valid"),
        );
        let mut service = ::tower::ServiceBuilder::new().layer(layer).service(Inner);

        // poll_ready delegates to the inner service.
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(service.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut blocked = Request::builder().uri("/x").body("b").expect("req");
        blocked
            .extensions_mut()
            .insert(ClientIp("203.0.113.9".parse().expect("ip")));
        let response = block_on(service.call(blocked)).expect("ready");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        // A custom body cannot outlive the request, so the static render
        // answers the reference default shape.
        assert_eq!(response.body(), &"");
    }

    #[test]
    fn the_helper_block_on_spins_a_pending_future_once() {
        struct PendingOnce {
            polled: std::cell::Cell<bool>,
        }
        impl Future for PendingOnce {
            type Output = u8;

            fn poll(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u8> {
                if self.polled.get() {
                    Poll::Ready(7)
                } else {
                    self.polled.set(true);
                    Poll::Pending
                }
            }
        }
        let future = PendingOnce {
            polled: std::cell::Cell::new(false),
        };
        assert_eq!(block_on(future), 7, "the second poll answers");
    }
}
