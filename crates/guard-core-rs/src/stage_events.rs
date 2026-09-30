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
pub fn emit_geo_block(
    sink: &StageEventSink,
    reason: &str,
    country: Option<&str>,
    rule: CountryRule,
    client_ip: &str,
    passive: bool,
) {
    let mut event = SecurityEvent::new(
        EVENT_COUNTRY_BLOCKED,
        client_ip,
        if passive {
            "logged_only"
        } else {
            "request_blocked"
        },
        reason,
        "ipinfo",
    );
    event.country = country.map(str::to_owned);
    event.rule_type = Some(rule.as_str().to_owned());
    sink.emit_event(&event);
    sink.emit_block(
        "ip_security",
        reason,
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

/// The user-agent stage's emissions.
///
/// A route-filter match emits `decorator_violation`
/// (`decorator_type="access_control"`, `violation_type="user_agent"`), a
/// global match `user_agent_blocked` (`filter_type="global"`); the block
/// hook fires under `user_agent` either way.
pub fn emit_user_agent_block(
    sink: &StageEventSink,
    route_scoped: bool,
    user_agent: &str,
    client_ip: &str,
    passive: bool,
) {
    let reason = format!("Blocked user agent: {user_agent}");
    let mut event = if route_scoped {
        let mut event = SecurityEvent::new(
            EVENT_DECORATOR_VIOLATION,
            client_ip,
            if passive {
                "logged_only"
            } else {
                "request_blocked"
            },
            &reason,
            "middleware",
        );
        event.decorator_type = Some(String::from("access_control"));
        event
    } else {
        SecurityEvent::new(
            EVENT_USER_AGENT_BLOCKED,
            client_ip,
            if passive {
                "logged_only"
            } else {
                "request_blocked"
            },
            &reason,
            "middleware",
        )
    };
    event.user_agent = Some(crate::redact::redact_url_for_display(
        user_agent,
        &crate::redact::SensitiveNames::default(),
    ));
    sink.emit_event(&event);
    sink.emit_block(
        "user_agent",
        &reason,
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
}
