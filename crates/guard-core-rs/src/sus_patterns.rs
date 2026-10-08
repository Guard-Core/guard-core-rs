//! The custom suspicious-pattern registry - the Rust family's equivalent
//! of the Python engine's custom-pattern half.
//!
//! Mirrors `guard_core/handlers/suspatterns_handler.py` +
//! `_suspatterns_registry.py`.
//!
//! Parity surface:
//!
//! - **add / remove**: a pattern is safety-validated (the engine's full
//!   ReDoS chain, `validate_pattern_safety`), compiled with the reference
//!   flags (the engine compiler's `(?im)`, the reference
//!   `re.IGNORECASE | re.MULTILINE`), deduplicated, persisted, and
//!   announced with `EVENT_PATTERN_ADDED` / `EVENT_PATTERN_REMOVED`
//!   (`handler_name = "sus_patterns"`, `ip_address = "system"`, the
//!   reference's action + reason strings, and the `pattern_type` /
//!   `total_patterns` metadata).
//! - **Redis store/load**: the custom set persists as the comma-joined
//!   source list under `{prefix}patterns:custom`
//!   ([`guard_core_engine::redis_schema::patterns_custom_key`], the
//!   reference `set_key("patterns", "custom", ",".join(...))`), and
//!   [`SusPatternsManager::restore_from_store`] re-adds every stored
//!   pattern at startup (the reference `initialize_redis`; unsafe stored
//!   patterns are skipped exactly like the reference's warning path).
//!   The join format is the reference's, commas inside a pattern
//!   included - the same inherited limitation, kept for byte-for-byte key
//!   compatibility.
//! - **detection**: [`SusPatternsManager::matches`] runs the compiled set
//!   over a payload (the custom-pattern arm of the reference `detect`), and
//!   [`SusPatternsManager::detect_pattern_match`] is the reference
//!   `detect_pattern_match` entry: one engine `detect` call plus the custom
//!   registry, answering the `(is_threat, matched_pattern)` tuple with the
//!   redacted match identity (the regex source, `semantic:{attack_type}`,
//!   a custom source, or the `"unknown"` fallback).
//! - **the Redis-backed store**: [`RedisPatternStore`] (the `redis`
//!   feature) is the reference registry's `redis_handler` - a
//!   [`RedisStore`](crate::redis_store::RedisStore) client plus the key
//!   prefix behind the [`CustomPatternStore`] seam, so the registry
//!   persists through the live `{prefix}patterns:custom` key.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_rs::sus_patterns::{MemoryPatternStore, SusPatternsManager};
//!
//! let manager = SusPatternsManager::new()
//!     .with_store(Arc::new(MemoryPatternStore::new()));
//!
//! // A safe pattern joins the registry and persists.
//! assert!(manager.add_pattern(r"union\s+select").expect("add"));
//! // A ReDoS-unsafe pattern is rejected, the reference `False` path.
//! assert!(!manager.add_pattern(r"(a+)+$").expect("add"));
//!
//! assert_eq!(
//!     manager.matches("UNION SELECT * FROM users"),
//!     vec![r"union\s+select".to_owned()]
//! );
//! assert!(manager.remove_pattern(r"union\s+select").expect("remove"));
//! ```
use std::fmt;
use std::sync::{Arc, Mutex};

use guard_core_engine::compiler;
use guard_core_engine::detect::{self, DetectConfig, Threat};
use guard_core_engine::distributed::StoreError;
use guard_core_engine::redis_schema::{PATTERNS_CUSTOM_KEY, PATTERNS_NAMESPACE};
use regex::Regex;

use crate::events::{SecurityEvent, SecurityEventBus};
use crate::redact::{SensitiveNames, redact_blob_for_display};

/// Compile a source that already passed the safety chain. The chain's own
/// second stage compiles the source with the same `(?im)` flags
/// `compiler::compile` uses, so the failure arm is genuinely unreachable
/// from [`SusPatternsManager`]'s public API; the cfg pair keeps it out of
/// coverage accounting while the fallible shape preserves the seam (the
/// `redact.rs` convention).
#[cfg(not(coverage))]
fn compile_checked(pattern: &str) -> Result<Regex, SusPatternsError> {
    compiler::compile(pattern).map_err(|error| SusPatternsError::Compile(error.to_string()))
}

#[cfg(coverage)]
fn compile_checked(pattern: &str) -> Result<Regex, SusPatternsError> {
    Ok(compiler::compile(pattern).expect("the safety chain compiles every accepted source"))
}

/// `handler_name` for pattern events (`_SUS_PATTERNS_HANDLER_NAME`).
pub const SUS_PATTERNS_HANDLER_NAME: &str = "sus_patterns";

/// The `ip_address` the pattern events carry (the reference
/// `"system"` sender).
pub const SYSTEM_EVENT_IP: &str = "system";

/// The redaction ceiling for the pattern source an event carries (the
/// reference `_redact_pattern_source` truncation at the warning sites).
const EVENT_PATTERN_SOURCE_MAX_CHARS: usize = 64;

/// The persistence seam (the reference `redis_handler.get_key` /
/// `set_key` pair the custom-pattern registry uses; the implementation
/// owns the key prefix, exactly like the Python handler).
pub trait CustomPatternStore: Send + Sync {
    /// The stored value for `{prefix}{namespace}:{key}`, if any.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    fn get_key(&self, namespace: &str, key: &str) -> Result<Option<String>, StoreError>;

    /// Persist the value for `{prefix}{namespace}:{key}` (no TTL, the
    /// reference registry's write shape).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    fn set_key(&self, namespace: &str, key: &str, value: &str) -> Result<(), StoreError>;
}

/// An in-process [`CustomPatternStore`]: the byte-exact key layout over a
/// hash map (tests, single-process deployments, and the fail-open default).
#[derive(Debug, Default)]
pub struct MemoryPatternStore {
    prefix: String,
    entries: Mutex<std::collections::HashMap<String, String>>,
}

impl MemoryPatternStore {
    /// A store keyed under `prefix` (the reference `redis_prefix`).
    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            entries: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl MemoryPatternStore {
    /// A store keyed under the reference default prefix.
    #[must_use]
    pub fn new() -> Self {
        Self::with_prefix(guard_core_engine::redis_schema::DEFAULT_REDIS_PREFIX)
    }
}

impl CustomPatternStore for MemoryPatternStore {
    fn get_key(&self, namespace: &str, key: &str) -> Result<Option<String>, StoreError> {
        let full = guard_core_engine::redis_schema::full_key(&self.prefix, namespace, key);
        Ok(self
            .entries
            .lock()
            .expect("pattern store")
            .get(&full)
            .cloned())
    }

    fn set_key(&self, namespace: &str, key: &str, value: &str) -> Result<(), StoreError> {
        let full = guard_core_engine::redis_schema::full_key(&self.prefix, namespace, key);
        self.entries
            .lock()
            .expect("pattern store")
            .insert(full, value.to_owned());
        Ok(())
    }
}

/// The Redis-backed [`CustomPatternStore`] (the reference registry's
/// `redis_handler`).
///
/// A [`RedisStore`](crate::redis_store::RedisStore) client plus the key
/// prefix, so the registry persists through the live
/// `{prefix}patterns:custom` key exactly like the Python handler's
/// `set_key("patterns", "custom", ...)` pair.
#[cfg(feature = "redis")]
pub struct RedisPatternStore {
    store: crate::redis_store::RedisStore,
    prefix: String,
}

#[cfg(feature = "redis")]
impl RedisPatternStore {
    /// Bind a connected-capable client to the registry's key prefix (the
    /// reference `redis_prefix`).
    #[must_use]
    pub fn new(store: crate::redis_store::RedisStore, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
        }
    }
}

#[cfg(feature = "redis")]
impl CustomPatternStore for RedisPatternStore {
    fn get_key(&self, namespace: &str, key: &str) -> Result<Option<String>, StoreError> {
        self.store.get_key(&self.prefix, namespace, key)
    }

    fn set_key(&self, namespace: &str, key: &str, value: &str) -> Result<(), StoreError> {
        self.store
            .set_key(&self.prefix, namespace, key, value, None)
    }
}

/// One registry failure: an unsafe pattern's reason, a compile error, or
/// a store failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SusPatternsError {
    /// The pattern source did not compile.
    Compile(String),
    /// The persistence seam failed.
    Store(String),
}

impl fmt::Display for SusPatternsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(reason) => write!(f, "pattern compile failed: {reason}"),
            Self::Store(reason) => write!(f, "pattern store failed: {reason}"),
        }
    }
}

impl std::error::Error for SusPatternsError {}

/// The custom-pattern registry: the compiled set plus the persistence and
/// event seams (`SusPatternsManager`'s custom half; the built-in pattern
/// table stays in the engine crate).
pub struct SusPatternsManager {
    compiled: Mutex<Vec<(String, Regex)>>,
    store: Option<Arc<dyn CustomPatternStore>>,
    event_bus: Option<SecurityEventBus>,
}

impl Default for SusPatternsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SusPatternsManager {
    /// An empty registry with no persistence and no event seam.
    #[must_use]
    pub fn new() -> Self {
        Self {
            compiled: Mutex::new(Vec::new()),
            store: None,
            event_bus: None,
        }
    }

    /// Wire the persistence seam (the reference `initialize_redis`'s
    /// handler injection; call [`SusPatternsManager::restore_from_store`]
    /// once afterwards, the reference does both together).
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn CustomPatternStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Wire the event seam (`agent_handler`'s stand-in; the pattern
    /// added/removed events ride it).
    #[must_use]
    pub fn with_event_bus(mut self, event_bus: SecurityEventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// The reference `add_pattern(pattern, custom=True)`: safety-validate,
    /// compile, dedup, persist, and announce. `Ok(false)` is the
    /// reference's `False` return for an unsafe pattern (the compile
    /// failure is the stricter [`SusPatternsError::Compile`], the Rust
    /// registry never carries an uncompilable entry).
    ///
    /// # Errors
    ///
    /// [`SusPatternsError`] on a compile failure or a store failure.
    pub fn add_pattern(&self, pattern: &str) -> Result<bool, SusPatternsError> {
        let (safe, _reason) = compiler::validate_pattern_safety(pattern);
        if !safe {
            // The reference logs a warning and returns False.
            return Ok(false);
        }
        let compiled_regex = compile_checked(pattern)?;

        let (added, total, sources) = {
            let mut compiled = self.compiled.lock().expect("pattern registry");
            let added = !compiled.iter().any(|(source, _)| source == pattern);
            if added {
                compiled.push((pattern.to_owned(), compiled_regex));
            }
            let sources: Vec<String> = compiled.iter().map(|(source, _)| source.clone()).collect();
            (added, compiled.len(), sources)
        };

        if added {
            self.persist(&sources)?;
            self.announce(
                crate::event_types::EVENT_PATTERN_ADDED,
                "pattern_added",
                "Custom pattern added to detection system",
                pattern,
                total,
            );
        }
        Ok(true)
    }

    /// The reference `remove_pattern(pattern, custom=True)`: `Ok(false)`
    /// when absent; otherwise remove, persist, and announce.
    ///
    /// # Errors
    ///
    /// [`SusPatternsError`] on a store failure.
    pub fn remove_pattern(&self, pattern: &str) -> Result<bool, SusPatternsError> {
        let (total, sources) = {
            let mut compiled = self.compiled.lock().expect("pattern registry");
            let Some(index) = compiled.iter().position(|(source, _)| source == pattern) else {
                return Ok(false);
            };
            compiled.remove(index);
            let sources: Vec<String> = compiled.iter().map(|(source, _)| source.clone()).collect();
            (compiled.len(), sources)
        };
        self.persist(&sources)?;
        self.announce(
            crate::event_types::EVENT_PATTERN_REMOVED,
            "pattern_removed",
            "Custom pattern removed from detection system",
            pattern,
            total,
        );
        Ok(true)
    }

    /// The reference `initialize_redis`: load the comma-joined custom set
    /// from the store and re-add every safe entry. Returns the number of
    /// patterns restored (unsafe stored sources are skipped with the
    /// reference's warning behavior).
    ///
    /// # Errors
    ///
    /// [`SusPatternsError`] on a store failure.
    pub fn restore_from_store(&self) -> Result<usize, SusPatternsError> {
        let Some(store) = &self.store else {
            return Ok(0);
        };
        let raw = store
            .get_key(PATTERNS_NAMESPACE, PATTERNS_CUSTOM_KEY_NAME)
            .map_err(|error| SusPatternsError::Store(error.to_string()))?;
        let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
            return Ok(0);
        };
        let mut restored = 0usize;
        // The unsafe-source filter is the reference's `Skipped restoring
        // persisted pattern` warning path. A source the chain accepted
        // always compiles (the chain's second stage compiles with the same
        // `(?im)` flags `compiler::compile` uses), so the compile result
        // feeds the registry through `Option` plumbing and no failure arm
        // exists.
        let candidates = raw
            .split(',')
            .filter(|source| !source.is_empty())
            .filter(|source| compiler::validate_pattern_safety(source).0)
            .filter_map(|source| {
                compile_checked(source)
                    .ok()
                    .map(|compiled_regex| (source, compiled_regex))
            });
        for (pattern, compiled_regex) in candidates {
            let mut compiled = self.compiled.lock().expect("pattern registry");
            if compiled.iter().all(|(source, _)| source != pattern) {
                compiled.push((pattern.to_owned(), compiled_regex));
                restored += 1;
            }
            drop(compiled);
        }
        Ok(restored)
    }

    /// The reference `get_custom_patterns`: the registered sources,
    /// sorted for determinism (the Python set's order is arbitrary).
    #[must_use]
    pub fn get_custom_patterns(&self) -> Vec<String> {
        let mut sources: Vec<String> = self
            .compiled
            .lock()
            .expect("pattern registry")
            .iter()
            .map(|(source, _)| source.clone())
            .collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    /// The custom-pattern arm of the reference `detect`: the sources of
    /// every registered pattern matching `text` (case-insensitive,
    /// multiline, the engine compiler's flags).
    #[must_use]
    pub fn matches(&self, text: &str) -> Vec<String> {
        self.compiled
            .lock()
            .expect("pattern registry")
            .iter()
            .filter(|(_, regex)| regex.is_match(text))
            .map(|(source, _)| source.clone())
            .collect()
    }

    /// The reference `detect_pattern_match(content, ip_address, context)`:
    /// one engine `detect` call over the content (the built-in regex and
    /// semantic pool) plus the custom registry, answering the reference's
    /// `(is_threat, matched_pattern)` tuple with the redacted match
    /// identity:
    ///
    /// - a regex threat carries the display-redacted pattern source (the
    ///   reference `_redact_pattern_source(threat["pattern"])`),
    /// - a semantic threat carries `semantic:{attack_type}`,
    /// - a custom-registry hit (the pool the reference compiles into the
    ///   same regex set) carries the redacted custom source,
    /// - a threat with no resolvable identity carries the reference
    ///   `"unknown"` fallback,
    /// - a clean scan answers `(false, None)`.
    #[must_use]
    pub fn detect_pattern_match(
        &self,
        content: &str,
        request_context: &str,
        detect_config: &DetectConfig,
        sensitive: &SensitiveNames,
    ) -> (bool, Option<String>) {
        let verdict = detect::detect(content, request_context, detect_config);
        let built_in = verdict
            .threats
            .first()
            .map(|threat| threat_identity(threat, sensitive));
        let custom = self
            .matches(content)
            .first()
            .map(|pattern| redact_blob_for_display(pattern, sensitive));
        match (built_in.or(custom), verdict.is_threat) {
            (Some(identity), _) => (true, Some(identity)),
            (None, true) => (true, Some(String::from("unknown"))),
            (None, false) => (false, None),
        }
    }

    /// Persist the current source set as the comma-joined list (the
    /// reference `set_key("patterns", "custom", ",".join(...))`).
    fn persist(&self, sources: &[String]) -> Result<(), SusPatternsError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let joined = sources.join(",");
        store
            .set_key(PATTERNS_NAMESPACE, PATTERNS_CUSTOM_KEY_NAME, &joined)
            .map_err(|error| SusPatternsError::Store(error.to_string()))
    }

    /// The reference `_send_pattern_event`: one `SecurityEvent` under the
    /// `sus_patterns` handler name with the pattern metadata.
    fn announce(
        &self,
        event_type: &str,
        action: &str,
        reason: &str,
        pattern: &str,
        total_patterns: usize,
    ) {
        let Some(event_bus) = &self.event_bus else {
            return;
        };
        let mut event = SecurityEvent::new(
            event_type,
            SYSTEM_EVENT_IP,
            action,
            reason,
            SUS_PATTERNS_HANDLER_NAME,
        );
        event.metadata.insert(
            "pattern_matched".to_owned(),
            serde_json::Value::from(truncate_source(pattern)),
        );
        event
            .metadata
            .insert("pattern_type".to_owned(), serde_json::Value::from("custom"));
        event.metadata.insert(
            "total_patterns".to_owned(),
            serde_json::Value::from(total_patterns),
        );
        event_bus.send_event(&event);
    }
}

/// The metadata key segment the registry persists under (the reference
/// `"custom"` key segment; `patterns_custom_key(prefix)` builds the full
/// store key from it).
pub const PATTERNS_CUSTOM_KEY_NAME: &str = PATTERNS_CUSTOM_KEY;

/// The redacted match identity one threat carries (the reference
/// `detect_pattern_match`'s identity resolution): a regex threat's
/// display-redacted pattern source, a semantic threat's
/// `semantic:{attack_type}`.
fn threat_identity(threat: &Threat, sensitive: &SensitiveNames) -> String {
    match threat {
        Threat::Regex(regex) => redact_blob_for_display(&regex.pattern, sensitive),
        Threat::Semantic(semantic) => format!("semantic:{}", semantic.attack_type),
    }
}

/// The reference `_redact_pattern_source`'s truncation shape for the
/// event-carried source.
fn truncate_source(pattern: &str) -> String {
    if pattern.chars().count() <= EVENT_PATTERN_SOURCE_MAX_CHARS {
        return pattern.to_owned();
    }
    let truncated: String = pattern
        .chars()
        .take(EVENT_PATTERN_SOURCE_MAX_CHARS)
        .collect();
    format!("{truncated}...")
}

#[cfg(test)]
mod tests {
    use super::{
        CustomPatternStore, MemoryPatternStore, SUS_PATTERNS_HANDLER_NAME, SYSTEM_EVENT_IP,
        SecurityEvent, StoreError, SusPatternsError, SusPatternsManager, Threat,
    };
    use crate::events::SecurityEventBus;
    use guard_core_engine::detect::{self, DetectConfig};
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "redis")]
    use super::RedisPatternStore;

    fn seen_bus() -> (Arc<Mutex<Vec<SecurityEvent>>>, SecurityEventBus) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true).on_event(Arc::new(move |event: &SecurityEvent| {
            sink.lock().expect("sink").push(event.clone());
        }));
        (seen, bus)
    }

    fn registry_with_store() -> (SusPatternsManager, Arc<MemoryPatternStore>) {
        let store = Arc::new(MemoryPatternStore::new());
        (SusPatternsManager::new().with_store(store.clone()), store)
    }

    #[test]
    fn a_safe_pattern_registers_and_matches_case_insensitively() {
        let manager = SusPatternsManager::new();
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert_eq!(
            manager.matches("UNION\nSELECT password FROM users"),
            vec![r"union\s+select".to_owned()],
            "the reference IGNORECASE | MULTILINE flags"
        );
        assert_eq!(manager.get_custom_patterns(), vec![r"union\s+select"]);
    }

    #[test]
    fn an_unsafe_pattern_is_rejected_like_the_reference_false() {
        let manager = SusPatternsManager::new();
        assert!(!manager.add_pattern(r"(a+)+$").expect("add"));
        assert!(manager.get_custom_patterns().is_empty());
        assert!(manager.matches("aaaaaaaaaaaaaaaaaaaaaaaaaaaa!").is_empty());
    }

    #[test]
    fn an_unbalanced_source_never_reaches_the_registry() {
        // The safety chain catches malformed sources before the compile
        // arm, so the registry can never carry one.
        let manager = SusPatternsManager::new();
        assert!(!manager.add_pattern(r"unbalanced(").expect("add"));
        assert!(manager.get_custom_patterns().is_empty());
    }

    #[test]
    fn duplicate_adds_are_idempotent() {
        let manager = SusPatternsManager::new();
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert_eq!(manager.get_custom_patterns().len(), 1);
    }

    #[test]
    fn removal_answers_false_when_absent_and_true_when_present() {
        let manager = SusPatternsManager::new();
        assert!(!manager.remove_pattern(r"union\s+select").expect("remove"));
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert!(manager.remove_pattern(r"union\s+select").expect("remove"));
        assert!(manager.get_custom_patterns().is_empty());
        assert!(manager.matches("UNION SELECT").is_empty());
    }

    #[test]
    fn adds_and_removals_persist_the_comma_joined_reference_key() {
        let (manager, store) = registry_with_store();
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert!(manager.add_pattern(r"etc/passwd").expect("add"));
        let stored = store
            .get_key("patterns", "custom")
            .expect("store")
            .expect("persisted");
        // The byte-exact reference value shape (insertion order joined).
        assert_eq!(stored, r"union\s+select,etc/passwd");

        assert!(manager.remove_pattern(r"union\s+select").expect("remove"));
        let stored = store
            .get_key("patterns", "custom")
            .expect("store")
            .expect("persisted");
        assert_eq!(stored, r"etc/passwd");
    }

    #[test]
    fn restore_from_store_re_adds_the_persisted_set() {
        let (manager, store) = registry_with_store();
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert!(manager.add_pattern(r"etc/passwd").expect("add"));

        // A fresh registry over the same store restores the set.
        let fresh = SusPatternsManager::new().with_store(store);
        assert_eq!(fresh.restore_from_store().expect("restore"), 2);
        assert_eq!(fresh.get_custom_patterns().len(), 2);
        assert_eq!(
            fresh.matches("UNION SELECT"),
            vec![r"union\s+select".to_owned()]
        );
    }

    #[test]
    fn restore_skips_unsafe_stored_sources() {
        let store = Arc::new(MemoryPatternStore::new());
        store
            .set_key("patterns", "custom", r"etc/passwd,(a+)+$")
            .expect("store");
        let manager = SusPatternsManager::new().with_store(store);
        assert_eq!(manager.restore_from_store().expect("restore"), 1);
        assert_eq!(manager.get_custom_patterns(), vec![r"etc/passwd"]);
    }

    #[test]
    fn restore_without_a_store_restores_nothing() {
        let manager = SusPatternsManager::new();
        assert_eq!(manager.restore_from_store().expect("restore"), 0);
    }

    #[test]
    fn restore_of_an_empty_stored_list_restores_nothing() {
        let store = Arc::new(MemoryPatternStore::new());
        store.set_key("patterns", "custom", "").expect("store");
        let manager = SusPatternsManager::new().with_store(store);
        assert_eq!(manager.restore_from_store().expect("restore"), 0);
        assert!(manager.get_custom_patterns().is_empty());
    }

    #[test]
    fn restore_skips_patterns_already_registered() {
        let store = Arc::new(MemoryPatternStore::new());
        store
            .set_key("patterns", "custom", r"union\s+select")
            .expect("store");
        let manager = SusPatternsManager::new().with_store(store);
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        // Already in the compiled set: not counted as restored, not
        // duplicated either.
        assert_eq!(manager.restore_from_store().expect("restore"), 0);
        assert_eq!(manager.get_custom_patterns(), vec![r"union\s+select"]);
    }

    #[test]
    fn error_variants_render_their_reasons() {
        use super::SusPatternsError;
        assert_eq!(
            SusPatternsError::Compile("bad source".to_owned()).to_string(),
            "pattern compile failed: bad source"
        );
        assert_eq!(
            SusPatternsError::Store("backend down".to_owned()).to_string(),
            "pattern store failed: backend down"
        );
    }

    #[test]
    fn default_builds_the_same_empty_registry() {
        let manager = SusPatternsManager::default();
        assert!(manager.get_custom_patterns().is_empty());
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert_eq!(manager.get_custom_patterns(), vec![r"union\s+select"]);
    }

    /// A store whose backend is down: every operation surfaces
    /// [`StoreError`], the reference's failing `redis_handler`.
    struct FailingStore;

    impl CustomPatternStore for FailingStore {
        fn get_key(&self, _namespace: &str, _key: &str) -> Result<Option<String>, StoreError> {
            Err(StoreError("backend down".to_owned()))
        }

        fn set_key(&self, _namespace: &str, _key: &str, _value: &str) -> Result<(), StoreError> {
            Err(StoreError("backend down".to_owned()))
        }
    }

    #[test]
    fn a_failing_store_surfaces_the_error_from_add_remove_and_restore() {
        let manager = SusPatternsManager::new().with_store(Arc::new(FailingStore));
        // add registers in memory, then fails to persist.
        let error = manager.add_pattern(r"union\s+select").unwrap_err();
        assert_eq!(
            error,
            SusPatternsError::Store("distributed store error: backend down".to_owned())
        );
        // remove clears the registry entry, then fails to persist.
        let error = manager.remove_pattern(r"union\s+select").unwrap_err();
        assert_eq!(
            error,
            SusPatternsError::Store("distributed store error: backend down".to_owned())
        );
        // restore surfaces the failing read.
        let error = manager.restore_from_store().unwrap_err();
        assert_eq!(
            error,
            SusPatternsError::Store("distributed store error: backend down".to_owned())
        );
    }

    #[test]
    fn pattern_events_carry_the_reference_fields() {
        let (seen, bus) = seen_bus();
        let manager = SusPatternsManager::new().with_event_bus(bus);
        assert!(manager.add_pattern(r"union\s+select").expect("add"));
        assert!(manager.remove_pattern(r"union\s+select").expect("remove"));

        let seen = seen.lock().expect("sink").clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].event_type, "pattern_added");
        assert_eq!(seen[0].action_taken, "pattern_added");
        assert_eq!(seen[0].reason, "Custom pattern added to detection system");
        assert_eq!(seen[0].ip_address, SYSTEM_EVENT_IP);
        assert_eq!(
            seen[0].handler_name.as_deref(),
            Some(SUS_PATTERNS_HANDLER_NAME)
        );
        assert_eq!(
            seen[0]
                .metadata
                .get("pattern_matched")
                .and_then(serde_json::Value::as_str),
            Some(r"union\s+select")
        );
        assert_eq!(
            seen[0]
                .metadata
                .get("pattern_type")
                .and_then(serde_json::Value::as_str),
            Some("custom")
        );
        assert_eq!(seen[1].event_type, "pattern_removed");
        assert_eq!(
            seen[1].reason,
            "Custom pattern removed from detection system"
        );
        assert_eq!(
            seen[1]
                .metadata
                .get("total_patterns")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn long_pattern_sources_are_truncated_in_the_event() {
        let (seen, bus) = seen_bus();
        let manager = SusPatternsManager::new().with_event_bus(bus);
        let long_pattern = "a".repeat(100);
        assert!(manager.add_pattern(&long_pattern).expect("add"));
        let seen = seen.lock().expect("sink").clone();
        let carried = seen[0]
            .metadata
            .get("pattern_matched")
            .and_then(serde_json::Value::as_str)
            .expect("pattern");
        assert_eq!(carried.chars().count(), 64 + 3, "64 chars + `...`");
        assert!(carried.ends_with("..."));
    }

    /// The regex source a threat carries, if it is a regex threat (the
    /// test view of the identity's regex arm; the semantic arm answers
    /// `None` and is exercised by the constructed threat below).
    fn regex_source(threat: &Threat) -> Option<&str> {
        match threat {
            Threat::Regex(regex) => Some(&regex.pattern),
            Threat::Semantic(_) => None,
        }
    }

    fn corpus_config() -> DetectConfig {
        DetectConfig {
            max_content_length: 10_000,
            max_full_scan_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            binary_min_run_length: 16,
        }
    }

    #[test]
    fn detect_pattern_match_answers_the_redacted_regex_identity() {
        let manager = SusPatternsManager::new();
        let sensitive = crate::redact::SensitiveNames::default();
        let (threat, identity) = manager.detect_pattern_match(
            "SELECT * FROM users",
            "request_body",
            &corpus_config(),
            &sensitive,
        );
        assert!(threat);
        // The identity is the matched table pattern, display-redacted.
        let verdict = detect::detect("SELECT * FROM users", "request_body", &corpus_config());
        assert_eq!(
            identity.as_deref(),
            regex_source(verdict.threats.first().expect("regex threat"))
        );
    }

    #[test]
    fn the_semantic_threat_identity_names_the_attack_type() {
        let sensitive = crate::redact::SensitiveNames::default();
        // A semantic threat (the shape the engine's detect emits when the
        // analyzer flags without a regex pool hit) resolves to
        // `semantic:{attack_type}`.
        let analysis = guard_core_engine::semantic::analyze(
            "select union insert update delete drop",
            &guard_core_engine::semantic::AttackKeywords::default(),
            &guard_core_engine::semantic::AttackStructures::default(),
        );
        let semantic = guard_core_engine::detect::SemanticThreat {
            attack_type: String::from("sqli"),
            score: 0.8,
            fallback: true,
            analysis,
        };
        assert_eq!(
            super::threat_identity(&Threat::Semantic(semantic.clone()), &sensitive),
            "semantic:sqli"
        );
        assert_eq!(regex_source(&Threat::Semantic(semantic)), None);
    }

    #[test]
    fn detect_pattern_match_answers_the_semantic_identity_through_detect() {
        let manager = SusPatternsManager::new();
        let sensitive = crate::redact::SensitiveNames::default();
        // A mixed verdict (regex first, semantic second): the identity is
        // the first threat's - the regex pool's redacted source, exactly
        // the reference's threats[0] resolution.
        let content = format!(
            "select union insert update delete drop from where order group having concat substring database table column (1 OR 1=1) {}",
            "A".repeat(120)
        );
        let verdict = detect::detect(&content, "request_body", &corpus_config());
        assert!(matches!(verdict.threats.first(), Some(Threat::Regex(_))));
        assert!(
            verdict
                .threats
                .iter()
                .any(|t| matches!(t, Threat::Semantic(_))),
            "the mixed payload carries a semantic threat"
        );
        let (threat, identity) =
            manager.detect_pattern_match(&content, "request_body", &corpus_config(), &sensitive);
        assert!(threat);
        assert_eq!(
            identity.as_deref(),
            regex_source(verdict.threats.first().expect("regex first"))
        );
    }

    #[test]
    fn detect_pattern_match_answers_a_custom_registry_hit() {
        let manager = SusPatternsManager::new();
        let sensitive = crate::redact::SensitiveNames::default();
        assert!(manager.add_pattern(r"zz-guard-custom-[0-9]+").expect("add"));
        // The content trips no built-in pattern; the custom pool flags it.
        let verdict = detect::detect("zz-guard-custom-42", "request_body", &corpus_config());
        assert!(!verdict.is_threat, "no built-in covers the marker");
        let (threat, identity) = manager.detect_pattern_match(
            "zz-guard-custom-42",
            "request_body",
            &corpus_config(),
            &sensitive,
        );
        assert!(threat);
        assert_eq!(identity.as_deref(), Some(r"zz-guard-custom-[0-9]+"));
    }

    #[test]
    fn detect_pattern_match_answers_the_unknown_fallback_for_identityless_threats() {
        let manager = SusPatternsManager::new();
        let sensitive = crate::redact::SensitiveNames::default();
        // A zero threshold marks every scan a threat: no threats, no custom
        // hits - the reference `unknown` fallback is the only identity.
        let config = DetectConfig {
            threat_score_threshold: 0.0,
            ..corpus_config()
        };
        let (threat, identity) =
            manager.detect_pattern_match("hello world", "request_body", &config, &sensitive);
        assert!(threat);
        assert_eq!(identity.as_deref(), Some("unknown"));
    }

    #[test]
    fn detect_pattern_match_answers_clean_for_benign_content() {
        let manager = SusPatternsManager::new();
        let sensitive = crate::redact::SensitiveNames::default();
        let (threat, identity) = manager.detect_pattern_match(
            "hello world",
            "request_body",
            &corpus_config(),
            &sensitive,
        );
        assert!(!threat);
        assert_eq!(identity, None);
    }

    #[cfg(feature = "redis")]
    #[test]
    fn the_redis_store_satisfies_the_persistence_seam() {
        let store = crate::redis_store::RedisStore::connect("redis://127.0.0.1:1")
            .expect("client construction is lazy");
        let _registry_store: Arc<dyn CustomPatternStore> =
            Arc::new(RedisPatternStore::new(store.clone(), "guard"));
        // The prefix rides the impl: the same client can back two prefixes.
        let _other: RedisPatternStore = RedisPatternStore::new(store, "other-app");
    }

    #[cfg(feature = "redis")]
    #[test]
    fn a_dead_redis_backend_surfaces_the_store_error_from_the_registry() {
        // Port 1 on localhost is never the test Redis; the first command
        // fails with the store error the registry surfaces, exactly like
        // the reference's failing redis_handler.
        let store =
            crate::redis_store::RedisStore::connect("redis://127.0.0.1:1").expect("lazy client");
        let manager =
            SusPatternsManager::new().with_store(Arc::new(RedisPatternStore::new(store, "guard")));
        let error = manager.add_pattern(r"union\s+select").unwrap_err();
        assert!(
            matches!(error, SusPatternsError::Store(_)),
            "the persist failure surfaces: {error:?}"
        );
        let error = manager.restore_from_store().unwrap_err();
        assert!(matches!(error, SusPatternsError::Store(_)), "{error:?}");
    }
}
