//! The data contracts the reference passes between the configuration
//! surface, the block hook, and the response-side pass.
//!
//! - [`BlockPayload`] is the reference `on_block` payload, key for key
//!   (`build_block_payload`, which stays facade-side next to the
//!   redaction it runs the path through).
//! - [`RequestBits`] / [`ResponseBits`] are the plain views the response
//!   processor reads and the adapter fill in; [`ResponseModifierFn`] is
//!   the reference `custom_response_modifier` seam over them.
//!
//! The types live in the engine so the unified `SecurityConfig` surface
//! (the next slice of the fieldization train) can type every hook field
//! without reaching into a framework layer; the facade re-exports them
//! under their historical paths.

use std::collections::BTreeMap;
use std::sync::Arc;

/// The check names the reference never fires the block hook for
/// (`ON_BLOCK_EXCLUDED_CHECK_NAMES`): the two application-authored checks
/// and the HTTPS redirect, which is not a block.
pub const ON_BLOCK_EXCLUDED_CHECK_NAMES: [&str; 3] =
    ["custom_request", "custom_validators", "https_enforcement"];

/// The reference block payload, key for key
/// (`build_block_payload`). `path` arrives pre-redacted;
/// `status_code` is `None` on the passive-mode path, where no response is
/// ever sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPayload {
    /// The emitting check (`rate_limit`, `ip_security`, ...).
    pub check_name: String,
    /// Why, the reference reason string.
    pub reason: String,
    /// The trigger description when the check carries one.
    pub trigger_info: String,
    /// Whether the pipeline runs in passive (log-only) mode.
    pub passive_mode: bool,
    /// The resolved client identity.
    pub client_ip: String,
    /// The redacted request path.
    pub path: String,
    /// The HTTP method.
    pub method: String,
    /// The block answer's status, `None` on the passive path.
    pub status_code: Option<u16>,
}

/// The `on_block` callback type: sync, best-effort, never fatal
/// (`SecurityConfig.on_block`).
pub type OnBlockHook = Arc<dyn Fn(&BlockPayload) + Send + Sync>;

/// The `on_error` callback type (`SecurityConfig.on_error`, the reference
/// `Callable[[str, BaseException, dict], None]`).
///
/// Arguments: the pipeline stage name, the error message, and the metadata
/// pairs. Sync, best-effort, never fatal - a panicking hook is the
/// caller's `catch_unwind`, exactly like the block hook.
pub type OnErrorFn = Arc<dyn Fn(&str, &str, &BTreeMap<String, String>) + Send + Sync>;

/// The plain request view the response-side pass reads: method, path,
/// resolved client identity, and the `Origin` header when the request
/// carried one.
#[derive(Debug, Clone, Default)]
pub struct RequestBits {
    /// The HTTP method.
    pub method: String,
    /// The request path (query included when present).
    pub url_path: String,
    /// The resolved client identity (empty when the connection carries
    /// none, e.g. a unix-socket listener).
    pub client_ip: String,
    /// The `Origin` header value.
    pub origin: Option<String>,
}

/// The mutable response view the response-side pass and the
/// `custom_response_modifier` seam write.
///
/// The status and body pass through untouched, the headers gain the
/// security-header set and the CORS verdict; `body` is `None` when the
/// response carries none or it is not buffered.
#[derive(Debug, Clone, Default)]
pub struct ResponseBits {
    /// The response status code.
    pub status: u16,
    /// The buffered body prefix when one is available.
    pub body: Option<String>,
    /// The headers the pass adds (security headers, CORS verdict).
    pub headers: BTreeMap<String, String>,
}

/// The `custom_response_modifier` callback type
/// (`SecurityConfig.custom_response_modifier`).
///
/// The reference `Callable[[GuardResponse], Awaitable[GuardResponse]]`:
/// mutates the forwarded response's view in place before it leaves the
/// pipeline.
pub type ResponseModifierFn = Arc<dyn Fn(&mut ResponseBits) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_bits_are_constructible_and_default() {
        let payload = BlockPayload {
            check_name: String::from("rate_limit"),
            reason: String::from("Rate limit exceeded"),
            trigger_info: String::new(),
            passive_mode: false,
            client_ip: String::from("192.0.2.1"),
            path: String::from("/login"),
            method: String::from("GET"),
            status_code: Some(429),
        };
        assert_eq!(payload.status_code, Some(429));

        let bits = ResponseBits::default();
        assert_eq!(bits.status, 0);
        assert!(bits.body.is_none());
        assert!(bits.headers.is_empty());

        let bits = RequestBits::default();
        assert!(bits.client_ip.is_empty());
        assert!(bits.origin.is_none());
    }

    #[test]
    fn hooks_receive_their_views() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let hook: OnBlockHook = Arc::new(move |payload: &BlockPayload| {
            sink.lock().expect("sink").push(payload.check_name.clone());
        });
        let payload = BlockPayload {
            check_name: String::from("ip_security"),
            reason: String::new(),
            trigger_info: String::new(),
            passive_mode: true,
            client_ip: String::new(),
            path: String::new(),
            method: String::new(),
            status_code: None,
        };
        hook(&payload);
        assert_eq!(seen.lock().expect("sink").as_slice(), ["ip_security"]);

        let errors = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&errors);
        let on_error: OnErrorFn = Arc::new(move |stage: &str, message: &str, _| {
            sink.lock()
                .expect("sink")
                .push((stage.to_owned(), message.to_owned()));
        });
        let mut metadata = BTreeMap::new();
        metadata.insert(String::from("k"), String::from("v"));
        on_error("cloud_fetch", "boom", &metadata);
        assert_eq!(
            errors.lock().expect("sink").as_slice(),
            [("cloud_fetch".to_owned(), "boom".to_owned())]
        );

        let modifier: ResponseModifierFn = Arc::new(|bits: &mut ResponseBits| {
            bits.headers
                .insert(String::from("x-modified"), String::from("1"));
        });
        let mut bits = ResponseBits::default();
        modifier(&mut bits);
        assert_eq!(
            bits.headers.get("x-modified").map(String::as_str),
            Some("1")
        );
    }
}
