// The suite's `assert!(x.is_empty())` idiom is pervasive (120+ sites) and several
// subjects carry no `PartialEq`, so clippy 1.99's new `assert_is_empty` lint
// (suggest `assert_eq!(x, [])` for the failure printout) is allowed crate-wide
// rather than rewriting the assertion surface in a release train.
#![allow(unknown_lints)] // the lint name below postdates the 1.92 MSRV clippy
#![allow(clippy::assert_is_empty)]

pub mod behavior;
pub mod binary_islands;
pub mod body_scan;
pub mod cloud_fetch;
pub mod cloud_provider;
pub mod compiler;
pub mod cors;
pub mod custom_checks;
pub mod decorators;
pub mod detect;
pub mod detection_exclusions;
pub mod distributed;
pub mod dynamic_rules;
pub mod emergency_mode;
pub mod geo;
pub mod headers_auth;
pub mod https_enforcement;
pub mod ip_ban;
pub mod ip_gate;
pub mod json_walk;
pub mod multipart_scan;
pub mod patterns;
pub mod payload;
pub mod performance_monitor;
pub mod preprocessor;
pub mod rate_limit;
pub mod redis_schema;
pub mod redos;
pub mod referrer;
pub mod request_limits;
pub mod request_logging;
pub mod route_config;
pub mod security_config;
pub mod security_headers;
pub mod semantic;
pub mod time_window;
pub mod user_agent;
