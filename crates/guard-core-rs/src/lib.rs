// The suite's `assert!(x.is_empty())` idiom is pervasive (120+ sites) and several
// subjects carry no `PartialEq`, so clippy 1.99's new `assert_is_empty` lint
// (suggest `assert_eq!(x, [])` for the failure printout) is allowed crate-wide
// rather than rewriting the assertion surface in a release train.
#![allow(unknown_lints)] // the lint name below postdates the 1.92 MSRV clippy
#![allow(clippy::assert_is_empty)]

//! Framework-agnostic application-layer API security engine.
//!
//! Rust port of [guard-core](https://github.com/rennf93/guard-core)'s
//! detection engine. **Work in progress:** the CPU-bound detection pipeline
//! is the core, and the first pipeline stage has landed: the rate-limit and
//! dynamic-ban [`tower`] layer for Axum/tonic-shaped stacks. Handlers,
//! protocols, decorators, and other I/O layers are not yet ported.
//!
//! Re-exports the detection engine modules:
//!
//! - [`detection_exclusions`] - the per-route detection exclusion resolution
//!   and the multi-surface request scan (`scan_request`): excluded
//!   headers/params/body fields, enabled detection categories, and the
//!   detection scan-body toggle, resolved from the global config and the
//!   route config exactly as the reference's `_resolve_*` helpers do
//! - [`compiler`] - regex pattern compilation with LRU caching and ReDoS safety validation
//! - [`detect`] - the spec 4.0.2 detection pipeline entry point (`detect`, [`detect::DetectConfig`],
//!   [`detect::DetectVerdict`])
//! - [`preprocessor`] - unicode NFKC normalization, URL/HTML decoding, null byte removal,
//!   whitespace collapsing, and attack-preserving truncation
//! - [`semantic`] - token extraction, Shannon entropy, encoding layer detection, attack probability
//!   scoring, obfuscation detection, code injection risk analysis, and aggregate threat scoring
//! - [`cloud_provider`] - the cloud-provider blocking pipeline stage as a
//!   `tower::Layer` (403 "Cloud provider IP not allowed", region
//!   carve-outs, skip-state aware)
//! - [`geo`] - the geo country blocking pipeline stage as a `tower::Layer`
//!   (403 "Forbidden", loopback exemption, whitelist-skip only)
//! - [`tower`] - the rate-limit and dynamic IP ban pipeline stage as a
//!   `tower::Layer` (429 throttled shape, 403 banned shapes, exempt-IP
//!   handling, the auto-ban feeds, and passive mode)
//! - [`request_limits`] - the request size and content-type pipeline stage
//!   as a `tower::Layer` (413 size shape, 415 content-type shape, fail-secure
//!   500 on a junk content-length)
//! - [`headers_auth`] - the required-headers and authentication pipeline
//!   stage as a `tower::Layer` (dynamic 400 required-header shapes, fixed
//!   401 authentication shape, route rules with a global verifier
//!   fallback)
//! - [`event_types`] / [`events`] - the reference `EVENT_*` constants and
//!   the `SecurityEventBus` hook seam over the reference `SecurityEvent`
//!   record
//! - [`responses`] - the reference `custom_error_responses` map and the
//!   `on_block` block hook with the reference payload and exclusion set
//! - [`logging`] - the reference `log_activity` line shapes with the
//!   `muted_check_logs` and `log_sensitive_*` redaction knobs
//! - [`redact`] - the merged sensitive-name sets and the
//!   `[REDACTED]` redaction the log lines run through
//!
//! # Usage
//!
//! ```
//! use guard_core_rs::preprocessor;
//! use guard_core_rs::semantic::AttackKeywords;
//! use guard_core_rs::semantic::AttackStructures;
//! use guard_core_rs::semantic::{self};
//!
//! let raw = "<scr\u{200B}ipt>alert(1)</script>";
//! let clean = preprocessor::preprocess(raw, 10_000, true);
//!
//! let kw = AttackKeywords::default();
//! let st = AttackStructures::default();
//! let result = semantic::analyze(&clean, &kw, &st);
//! let score = semantic::get_threat_score(&result);
//!
//! assert!(score > 0.0);
//! ```

pub mod cloud_fetch;
pub mod cloud_provider;
pub mod custom_checks;
pub mod emergency_mode;
pub mod enrichment;
pub mod event_types;
pub mod events;
pub mod geo;
pub mod headers_auth;
pub mod https_enforcement;
pub mod logging;
pub mod metrics;
pub mod mmdb;
pub mod process_response;
pub mod redact;
#[cfg(feature = "redis")]
pub mod redis_store;
pub mod request_limits;
pub mod request_logging;
pub mod responses;
pub mod route_gates;
pub mod stage_events;
pub mod sus_patterns;
pub mod tower;
pub mod user_agent;

pub use guard_core_engine::compiler;
pub use guard_core_engine::detect;
pub use guard_core_engine::detection_exclusions;
pub use guard_core_engine::preprocessor;
pub use guard_core_engine::referrer;
pub use guard_core_engine::semantic;
pub use guard_core_engine::time_window;
