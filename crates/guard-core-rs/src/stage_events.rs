//! The stage event seam: the `on_block` payload and the `SecurityEventBus`
//! dispatch the guard stages fire on their blocks, so the observable
//! stream matches spec 12.
//!
//! The rate-limit stage carries its own observability knobs; this module
//! extracts the shared shape so the geo, cloud, and user-agent stages
//! emit exactly what the reference emits on the same paths:
//!
//! - the `on_block` hook (`build_block_payload` shape, the excluded check
//!   names never fired);
//! - the stage's `EVENT_*` event over the bus (`country_blocked`,
//!   `cloud_blocked`, `user_agent_blocked`, or `decorator_violation` for a
//!   route-scoped match), with `action_taken` `request_blocked` or
//!   `logged_only` under passive mode.
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, Mutex};
//!
//! use guard_core_rs::redact::SensitiveNames;
//! use guard_core_rs::responses::OnBlockHook;
//! use guard_core_rs::stage_events::StageEventSink;
//!
//! let sink = StageEventSink::new(None, None, SensitiveNames::default());
//! // With no hook and no bus the emissions are no-ops; the shape is what
//! // the stages share.
//! sink.emit_block("user_agent", "Blocked user agent: bot", "192.0.2.9", "/", "GET", Some(403), false);
//! ```
//!
//! With a hook installed the same call fires the reference payload; with a
//! bus it also dispatches the `SecurityEvent`.

use std::sync::Arc;

use crate::event_types::{
    EVENT_CLOUD_BLOCKED, EVENT_COUNTRY_BLOCKED, EVENT_DECORATOR_VIOLATION, EVENT_USER_AGENT_BLOCKED,
};
use crate::events::{SecurityEvent, SecurityEventBus};
use crate::redact::SensitiveNames;
use crate::responses::{OnBlockHook, build_block_payload, fire_block_hook};

/// The shared stage observability: the hook, the bus, and the redaction
/// sets the stage emissions run through. Clone-safe; install one per
/// stage.
#[derive(Clone, Default)]
pub struct StageEventSink {
    on_block: Option<OnBlockHook>,
    events: Option<Arc<SecurityEventBus>>,
    sensitive: Arc<SensitiveNames>,
}

impl core::fmt::Debug for StageEventSink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StageEventSink")
            .field("on_block", &self.on_block.is_some())
            .field("events", &self.events.is_some())
            .field("sensitive", &"SensitiveNames")
            .finish()
    }
}

impl StageEventSink {
    /// Build a sink over the hook, the bus, and the redaction sets (each
    /// optional; absent pieces make the corresponding emission a no-op,
    /// exactly like the reference's absent `agent_handler`).
    #[must_use]
    pub fn new(
        on_block: Option<OnBlockHook>,
        events: Option<Arc<SecurityEventBus>>,
        sensitive: SensitiveNames,
    ) -> Self {
        Self {
            on_block,
            events,
            sensitive: Arc::new(sensitive),
        }
    }

    /// Whether any emission would land (the stages skip composing when
    /// nothing observes).
    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.on_block.is_some() || self.events.is_some()
    }

    /// The block-payload half (`fire_block_hook` with the reference
    /// payload): `passive` sends the payload with no status code, active
    /// carries the block status.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_block(
        &self,
        check_name: &str,
        reason: &str,
        client_ip: &str,
        path: &str,
        method: &str,
        status: Option<u16>,
        passive: bool,
    ) {
        fire_block_hook(
            self.on_block.as_ref(),
            &build_block_payload(
                check_name,
                reason,
                "",
                passive,
                client_ip,
                path,
                method,
                if passive { None } else { status },
                &self.sensitive,
            ),
        );
    }

    /// The bus half: dispatch one composed event (the bus applies the
    /// event filter and swallows handler failures).
    pub fn emit_event(&self, event: &SecurityEvent) {
        if let Some(bus) = &self.events {
            bus.send_event(event);
        }
    }
}

/// Which list matched the geo verdict (the reference `rule_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountryRule {
    /// The `blocked_countries` list matched.
    Blacklist,
    /// A configured `whitelist_countries` missed.
    Whitelist,
}

impl CountryRule {
    /// The reference `rule_type` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blacklist => "country_blacklist",
            Self::Whitelist => "country_whitelist",
        }
    }
}

/// The geo stage's emissions (`check_country_access` / the config-level
/// country verdict): the `country_blocked` event with the matching rule
/// type and the block hook under `ip_security`.
///
/// The reference event is handler-direct (`ipinfo_handler
/// .check_country_access` -> `_send_geo_event`): it always reads
/// `request_blocked` (passive mode never flips it), it carries the
/// handler's own reason strings (`Country {c} is blocked` for the
/// blacklist, `Country {c} not in allowed list` for a whitelist miss),
/// and it only fires for a resolved country - both reference emitters
/// sit behind a resolved `country`. The block hook keeps the pipeline's
/// log reason and the passive suppression.
pub fn emit_geo_block(
    sink: &StageEventSink,
    log_reason: &str,
    country: Option<&str>,
    rule: CountryRule,
    client_ip: &str,
    passive: bool,
) {
    if let Some(country) = country {
        let reason = match rule {
            CountryRule::Blacklist => format!("Country {country} is blocked"),
            CountryRule::Whitelist => format!("Country {country} not in allowed list"),
        };
        let mut event = SecurityEvent::new(
            EVENT_COUNTRY_BLOCKED,
            client_ip,
            "request_blocked",
            &reason,
            "ipinfo",
        );
        event.country = Some(country.to_owned());
        event.rule_type = Some(rule.as_str().to_owned());
        sink.emit_event(&event);
    }
    sink.emit_block(
        "ip_security",
        log_reason,
        client_ip,
        "/",
        "",
        Some(403),
        passive,
    );
}

/// The cloud stage's emissions (`send_cloud_detection_event` plus the
/// block hook): the `cloud_blocked` event carrying the provider and
/// network, and the `cloud_provider` block payload.
pub fn emit_cloud_block(
    sink: &StageEventSink,
    provider: Option<&str>,
    network: Option<&str>,
    client_ip: &str,
    passive: bool,
) {
    let provider_name = provider.unwrap_or("unknown");
    let reason = format!("IP belongs to blocked cloud provider: {provider_name}");
    let mut event = SecurityEvent::new(
        EVENT_CLOUD_BLOCKED,
        client_ip,
        if passive {
            "logged_only"
        } else {
            "request_blocked"
        },
        &reason,
        "cloud",
    );
    event.metadata.insert(
        "cloud_provider".to_owned(),
        serde_json::Value::String(provider_name.to_owned()),
    );
    if let Some(network) = network {
        event.metadata.insert(
            "network".to_owned(),
            serde_json::Value::String(network.to_owned()),
        );
    }
    sink.emit_event(&event);
    sink.emit_block(
        "cloud_provider",
        &format!("Blocked cloud provider IP: {client_ip}"),
        client_ip,
        "/",
        "",
        Some(403),
        passive,
    );
}

/// The user-agent stage's emissions (`user_agent.py`).
///
/// A route-filter match emits `decorator_violation`
/// (`decorator_type` `access_control`, `violation_type` `user_agent`,
/// `blocked_user_agent` metadata, reason
/// `User agent '{ua}' blocked`), a global match `user_agent_blocked`
/// (`user_agent` metadata, `filter_type` `global`, reason
/// `User agent '{ua}' in global blocklist`); the user agent is the
/// header-value redaction either way, on the event field and in the
/// metadata, and the block hook fires under `user_agent` with the log
/// line's reason.
pub fn emit_user_agent_block(
    sink: &StageEventSink,
    route_scoped: bool,
    user_agent: &str,
    client_ip: &str,
    passive: bool,
) {
    // The reference redacts the UA before it reaches any event or log
    // (`redact_header_value_for_display` = the blob redaction).
    let redacted = crate::redact::redact_blob_for_display(user_agent, &sink.sensitive);
    let action = if passive {
        "logged_only"
    } else {
        "request_blocked"
    };
    let mut event = if route_scoped {
        let mut event = SecurityEvent::new(
            EVENT_DECORATOR_VIOLATION,
            client_ip,
            action,
            &format!("User agent '{redacted}' blocked"),
            "middleware",
        );
        event.decorator_type = Some(String::from("access_control"));
        event.metadata.insert(
            String::from("decorator_type"),
            serde_json::json!("access_control"),
        );
        event.metadata.insert(
            String::from("violation_type"),
            serde_json::json!("user_agent"),
        );
        event.metadata.insert(
            String::from("blocked_user_agent"),
            serde_json::json!(redacted),
        );
        event
    } else {
        let mut event = SecurityEvent::new(
            EVENT_USER_AGENT_BLOCKED,
            client_ip,
            action,
            &format!("User agent '{redacted}' in global blocklist"),
            "middleware",
        );
        event
            .metadata
            .insert(String::from("user_agent"), serde_json::json!(redacted));
        event
            .metadata
            .insert(String::from("filter_type"), serde_json::json!("global"));
        event
    };
    event.user_agent = Some(redacted.clone());
    sink.emit_event(&event);
    sink.emit_block(
        "user_agent",
        &format!("Blocked user agent: {redacted}"),
        client_ip,
        "/",
        "",
        Some(403),
        passive,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type BlockLog = Arc<Mutex<Vec<(String, String, Option<u16>)>>>;

    fn sink_with_hook() -> (StageEventSink, BlockLog) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink_for_hook = Arc::clone(&recorded);
        let hook: OnBlockHook = Arc::new(move |payload| {
            sink_for_hook.lock().expect("recorder").push((
                payload.check_name.clone(),
                payload.reason.clone(),
                payload.status_code,
            ));
        });
        (
            StageEventSink::new(Some(hook), None, SensitiveNames::default()),
            recorded,
        )
    }

    #[test]
    fn the_geo_emission_carries_the_rule_type_and_the_hook() {
        let (sink, recorded) = sink_with_hook();
        emit_geo_block(
            &sink,
            "IP from blocked country: CN",
            Some("CN"),
            CountryRule::Blacklist,
            "192.0.2.9",
            false,
        );
        let blocks = recorded.lock().expect("recorder").clone();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "ip_security");
        assert_eq!(blocks[0].2, Some(403));
    }

    #[test]
    fn the_cloud_emission_carries_provider_and_network() {
        let (sink, recorded) = sink_with_hook();
        emit_cloud_block(
            &sink,
            Some("AWS"),
            Some("203.0.113.0/24"),
            "192.0.2.9",
            false,
        );
        let blocks = recorded.lock().expect("recorder").clone();
        assert_eq!(blocks[0].0, "cloud_provider");
        assert_eq!(blocks[0].1, "Blocked cloud provider IP: 192.0.2.9");
    }

    #[test]
    fn the_ua_emission_splits_route_and_global_events() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let reader = Arc::clone(&seen);
        let bus = SecurityEventBus::new(true).on_event(Arc::new(move |event: &SecurityEvent| {
            reader
                .lock()
                .expect("reader")
                .push(event.event_type.clone());
        }));
        let sink = StageEventSink::new(None, Some(Arc::new(bus)), SensitiveNames::default());
        emit_user_agent_block(&sink, true, "bot/1.0", "192.0.2.9", false);
        emit_user_agent_block(&sink, false, "bot/1.0", "192.0.2.9", false);
        let types = seen.lock().expect("seen").clone();
        assert_eq!(
            types.as_slice(),
            ["decorator_violation", "user_agent_blocked"]
        );
    }

    #[test]
    fn passive_emissions_drop_the_status() {
        let (sink, recorded) = sink_with_hook();
        sink.emit_block(
            "user_agent",
            "Blocked user agent: bot",
            "192.0.2.9",
            "/",
            "GET",
            Some(403),
            true,
        );
        let blocks = recorded.lock().expect("recorder").clone();
        assert_eq!(blocks[0].2, None, "the passive payload carries no status");
    }

    fn bus_recorder() -> (Arc<Mutex<Vec<SecurityEvent>>>, Arc<SecurityEventBus>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink_log = Arc::clone(&log);
        let bus = Arc::new(SecurityEventBus::new(true).on_event(Arc::new(
            move |event: &SecurityEvent| {
                sink_log.lock().expect("sink").push(event.clone());
            },
        )));
        (log, bus)
    }

    fn bus_sink(bus: Arc<SecurityEventBus>) -> StageEventSink {
        StageEventSink::new(None, Some(bus), SensitiveNames::default())
    }

    #[test]
    fn the_geo_event_carries_the_handler_reason_and_request_blocked() {
        let (log, bus) = bus_recorder();
        let sink = bus_sink(bus);
        // The blacklist arm.
        emit_geo_block(
            &sink,
            "IP from blocked country: CN",
            Some("CN"),
            CountryRule::Blacklist,
            "192.0.2.9",
            false,
        );
        // The whitelist-miss arm.
        emit_geo_block(
            &sink,
            "IP from blocked country: RU",
            Some("RU"),
            CountryRule::Whitelist,
            "192.0.2.10",
            false,
        );
        // An unresolved country emits no event (the reference emitters sit
        // behind a resolved country).
        emit_geo_block(
            &sink,
            "IP unknown not in global allowlist/blocklist",
            None,
            CountryRule::Whitelist,
            "192.0.2.11",
            false,
        );

        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 2, "no event for an unresolved country");
        assert_eq!(events[0].reason, "Country CN is blocked");
        assert_eq!(events[0].action_taken, "request_blocked");
        assert_eq!(events[0].country.as_deref(), Some("CN"));
        assert_eq!(events[0].rule_type.as_deref(), Some("country_blacklist"));
        assert_eq!(events[0].handler_name.as_deref(), Some("ipinfo"));
        assert_eq!(events[1].reason, "Country RU not in allowed list");
        assert_eq!(events[1].rule_type.as_deref(), Some("country_whitelist"));
    }

    #[test]
    fn the_geo_event_stays_request_blocked_under_passive_mode() {
        // The reference geo event is handler-direct: no passive flip.
        let (log, bus) = bus_recorder();
        let sink = bus_sink(bus);
        emit_geo_block(
            &sink,
            "IP from blocked country: CN",
            Some("CN"),
            CountryRule::Blacklist,
            "192.0.2.9",
            true,
        );
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action_taken, "request_blocked");
    }

    #[test]
    fn the_ua_events_carry_the_reference_reasons_and_metadata() {
        let (log, bus) = bus_recorder();
        let sink = bus_sink(bus);
        emit_user_agent_block(&sink, true, "bot/1.0", "192.0.2.9", false);
        emit_user_agent_block(&sink, false, "bot/1.0", "192.0.2.9", false);

        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, EVENT_DECORATOR_VIOLATION);
        assert_eq!(events[0].reason, "User agent 'bot/1.0' blocked");
        assert_eq!(events[0].decorator_type.as_deref(), Some("access_control"));
        assert_eq!(events[0].metadata["violation_type"], "user_agent");
        assert_eq!(events[0].metadata["blocked_user_agent"], "bot/1.0");
        assert_eq!(events[1].event_type, EVENT_USER_AGENT_BLOCKED);
        assert_eq!(events[1].reason, "User agent 'bot/1.0' in global blocklist");
        assert_eq!(events[1].metadata["filter_type"], "global");
        assert_eq!(events[1].metadata["user_agent"], "bot/1.0");
    }

    #[test]
    fn the_sink_reports_installation_and_renders_debug() {
        let bare = StageEventSink::default();
        assert!(!bare.is_installed(), "no hook, no bus: nothing observes");
        assert!(format!("{bare:?}").starts_with("StageEventSink"));

        let (sink, _recorded) = sink_with_hook();
        assert!(sink.is_installed(), "a hook alone counts as installed");
    }

    #[test]
    fn passive_cloud_and_ua_events_flip_to_logged_only_and_cloud_skips_metadata() {
        let (log, bus) = bus_recorder();
        let sink = bus_sink(bus);

        // A passive cloud block: the event flips to logged_only, and a
        // match without network metadata carries none.
        emit_cloud_block(&sink, Some("GCP"), None, "192.0.2.9", true);
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action_taken, "logged_only");
        assert_eq!(events[0].metadata["cloud_provider"], "GCP");
        assert!(events[0].metadata.get("network").is_none());

        // A passive user-agent block flips the same way.
        emit_user_agent_block(&sink, false, "bot/1.0", "192.0.2.9", true);
        let events = log.lock().expect("sink").clone();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].action_taken, "logged_only");
    }
}
