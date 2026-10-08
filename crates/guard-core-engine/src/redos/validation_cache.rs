//! The disk-backed cache for the pattern-safety validator's expensive
//! layer: the reference `_validation_cache.py` (the PHP lane's
//! `Detection/Redos/ValidationCache.php` and the TS
//! `PatternValidationCache` port the same module).
//!
//! The cheap deterministic layers (dangerous constructs, compile check,
//! structural detectors) always re-run; only the empirical cost-verdict
//! outcome is cached, keyed by pattern and flags, so a process boot reuses
//! prior certifications instead of re-timing every custom pattern.
//!
//! File shape: a JSON object mapping `sha256(pattern 0x00 flags)` hex keys
//! to `{version, safe, reason}` entries; entries from a different engine
//! version are dropped on load, a corrupt file starts empty (the outcome
//! surfaces as [`LoadOutcome`] data - the engine keeps its no-logger
//! idiom), and a write is atomic (tmp file plus rename).
//!
//! # Example
//!
//! ```
//! use guard_core_engine::redos::validation_cache::{LoadOutcome, ValidationCache};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = std::env::temp_dir().join("guard-validation-cache-doctest");
//! let _ = std::fs::remove_dir_all(&dir);
//! std::fs::create_dir_all(&dir)?;
//! let path = dir.join("validation-cache.json");
//! let cache = ValidationCache::load(&path);
//! assert!(matches!(cache.outcome(), LoadOutcome::Absent));
//!
//! // First sight: the empirical chain runs, the verdict persists.
//! let (safe, _) = cache.validate_compat(r"^safe-\d+$");
//! assert!(safe);
//! assert!(path.is_file(), "the verdict landed on disk");
//!
//! // Second boot: the same pattern answers from the loaded file.
//! let reloaded = ValidationCache::load(&path);
//! assert!(reloaded.get(r"^safe-\d+$", true).is_some());
//! std::fs::remove_dir_all(&dir)?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Lowercase hex SHA-256 over `bytes` (the reference `hexdigest`).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The cache-invalidating engine identity (the crate version): bumped
/// with every release so verdicts from an older engine never load.
pub fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// How the cache file loaded (the reference's log-once outcomes, surfaced
/// as data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadOutcome {
    /// No file yet (first boot).
    Absent,
    /// The file parsed; entries from other engine versions were dropped
    /// (count named).
    Loaded { foreign_versions_dropped: usize },
    /// The file exists but is unreadable or corrupt: the cache starts
    /// empty (the reference logs a warning; the data rides here).
    Corrupt { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedEntry {
    version: String,
    safe: bool,
    reason: String,
}

/// The disk-backed pattern-validation cache.
pub struct ValidationCache {
    path: PathBuf,
    entries: Mutex<HashMap<String, CachedEntry>>,
    outcome: LoadOutcome,
}

impl std::fmt::Debug for ValidationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationCache")
            .field("path", &self.path)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl ValidationCache {
    /// Load (or start) the cache at `path`: a missing file starts empty
    /// ([`LoadOutcome::Absent`]), a corrupt or unreadable file starts
    /// empty ([`LoadOutcome::Corrupt`]), and entries stamped with another
    /// engine version drop on load.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let mut outcome = LoadOutcome::Absent;
        let mut entries = HashMap::new();
        match std::fs::File::open(path) {
            Err(_) => {}
            Ok(mut file) => {
                let mut raw = String::new();
                let read = file.read_to_string(&mut raw);
                match read.and_then(|_| {
                    serde_json::from_str::<HashMap<String, CachedEntry>>(&raw)
                        .map_err(|error| std::io::Error::other(error.to_string()))
                }) {
                    Ok(file) => {
                        let mut foreign = 0usize;
                        for (key, entry) in file {
                            if entry.version == engine_version() {
                                entries.insert(key, entry);
                            } else {
                                foreign += 1;
                            }
                        }
                        outcome = LoadOutcome::Loaded {
                            foreign_versions_dropped: foreign,
                        };
                    }
                    Err(error) => {
                        outcome = LoadOutcome::Corrupt {
                            detail: error.to_string(),
                        };
                    }
                }
            }
        }
        Self {
            path: path.to_path_buf(),
            entries: Mutex::new(entries),
            outcome,
        }
    }

    /// The load outcome (the caller logs it).
    #[must_use]
    pub fn outcome(&self) -> &LoadOutcome {
        &self.outcome
    }

    /// The reference `_key`: sha256 over the pattern, a `0x00` separator,
    /// and the flags char (`i` when case-insensitive).
    #[must_use]
    pub fn key(pattern: &str, ignore_case: bool) -> String {
        let mut keyed = pattern.as_bytes().to_vec();
        keyed.push(0u8);
        keyed.extend_from_slice(if ignore_case { b"i" } else { b"" });
        sha256_hex(&keyed)
    }

    /// The cached verdict, `None` when the pattern was never certified.
    #[must_use]
    pub fn get(&self, pattern: &str, ignore_case: bool) -> Option<(bool, String)> {
        let entries = self.entries.lock().expect("validation cache");
        entries
            .get(&Self::key(pattern, ignore_case))
            .map(|entry| (entry.safe, entry.reason.clone()))
    }

    /// Record one verdict and persist atomically (tmp file plus rename; a
    /// failed write leaves the in-memory entry and drops the persistence,
    /// the reference's logged-but-survivable outcome).
    pub fn put(&self, pattern: &str, ignore_case: bool, safe: bool, reason: &str) {
        let key = Self::key(pattern, ignore_case);
        let entry = CachedEntry {
            version: engine_version().to_owned(),
            safe,
            reason: reason.to_owned(),
        };
        let payload = {
            let mut entries = self.entries.lock().expect("validation cache");
            entries.insert(key, entry);
            serde_json::to_vec(&*entries)
        };
        // An in-memory map of strings and bools always serializes.
        let bytes = payload.expect("cache entries serialize");
        let tmp_path = self.path.with_extension("tmp");
        // Atomic publish: tmp write then rename. A failed rename leaves
        // the tmp behind for the next write to overwrite (the reference's
        // logged-but-survivable outcome).
        let written = std::fs::write(&tmp_path, bytes).is_ok();
        if written && std::fs::rename(&tmp_path, &self.path).is_ok() {
            return;
        }
        if written {
            let _ = std::fs::remove_file(&tmp_path);
        }
    }

    /// The cached validation entry point (the `validate_pattern_safety`
    /// compat shape): the cheap deterministic layers always re-run, the
    /// empirical cost-verdict layer answers from the cache on a hit and
    /// persists on a miss.
    #[must_use]
    pub fn validate_compat(&self, pattern: &str) -> (bool, String) {
        self.validate_with_flags(pattern, super::safety::default_flags().ignorecase)
    }

    /// [`ValidationCache::validate_compat`] with the flags char explicit
    /// (a pattern validated under different flags caches separately).
    #[must_use]
    pub fn validate_with_flags(&self, pattern: &str, ignore_case: bool) -> (bool, String) {
        let flags = if ignore_case {
            super::safety::default_flags()
        } else {
            super::ast::Flags::default()
        };
        // The cheap layers re-run every time.
        if let Some(construct) = super::prefilters::dangerous_construct_violation(pattern) {
            return (
                false,
                super::safety::SafetyReason::DangerousConstruct(construct).to_string(),
            );
        }
        if let Err(error) = super::safety::compile_failed(pattern, flags) {
            return (false, error);
        }
        if let Some((safe, reason)) = self.get(pattern, ignore_case) {
            return (safe, reason);
        }
        let verdict = super::safety::validate_pattern_safety(
            pattern,
            &super::safety::SafetyMode::CostVerdict {
                max_content_length: None,
            },
        );
        let (safe, reason) = (verdict.safe, verdict.reason.to_string());
        self.put(pattern, ignore_case, safe, &reason);
        (safe, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> (std::path::PathBuf, PathBuf) {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "guard-validation-cache-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("validation-cache.json");
        (dir, path)
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_file_starts_absent_and_empty() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        assert_eq!(cache.outcome(), &LoadOutcome::Absent);
        assert!(cache.get("anything", true).is_none());
        cleanup(&dir);
    }

    #[test]
    fn the_first_verdict_persists_and_a_second_boot_reuses_it() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        let (safe, _) = cache.validate_compat(r"^safe-\d+$");
        assert!(safe);
        assert!(path.is_file());

        let reloaded = ValidationCache::load(&path);
        assert_eq!(
            reloaded.outcome(),
            &LoadOutcome::Loaded {
                foreign_versions_dropped: 0
            }
        );
        let (safe, reason) = reloaded.get(r"^safe-\d+$", true).expect("cached");
        assert!(safe);
        assert!(!reason.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn a_corrupt_file_starts_empty_with_the_outcome_named() {
        let (dir, path) = tempdir();
        std::fs::write(&path, "{not json").expect("corrupt file");
        let cache = ValidationCache::load(&path);
        assert!(matches!(cache.outcome(), LoadOutcome::Corrupt { .. }));
        assert!(cache.get("anything", false).is_none());

        // The cache still validates and re-persists over the corruption.
        let (safe, _) = cache.validate_compat(r"^safe-\d+$");
        assert!(safe);
        let reloaded = ValidationCache::load(&path);
        assert!(reloaded.get(r"^safe-\d+$", true).is_some());
        cleanup(&dir);
    }

    #[test]
    fn foreign_version_entries_drop_on_load() {
        let (dir, path) = tempdir();
        let key = ValidationCache::key("some-pattern", true);
        let foreign = format!(r#"{{"{key}":{{"version":"0.0.1","safe":false,"reason":"stale"}}}}"#);
        std::fs::write(&path, foreign).expect("foreign cache");
        let cache = ValidationCache::load(&path);
        assert_eq!(
            cache.outcome(),
            &LoadOutcome::Loaded {
                foreign_versions_dropped: 1
            }
        );
        assert!(cache.get("some-pattern", true).is_none());
        cleanup(&dir);
    }

    #[test]
    fn the_cheap_layers_re_run_even_when_cached() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        // Seed the cache with a "safe" verdict for a dangerous pattern.
        cache.put("(a+)+$", true, true, "seeded");
        assert!(cache.get("(a+)+$", true).is_some());

        // The dangerous-construct layer fires before the cache answers.
        let (safe, reason) = cache.validate_compat("(a+)+$");
        assert!(!safe);
        assert!(reason.contains("dangerous") || !reason.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn the_flags_char_splits_the_cache_keys() {
        let key_case = ValidationCache::key("pattern", true);
        let key_plain = ValidationCache::key("pattern", false);
        assert_ne!(key_case, key_plain);
        // sha256 over the documented byte shape.
        let mut keyed = b"pattern".to_vec();
        keyed.push(0u8);
        keyed.extend_from_slice(b"i");
        assert_eq!(key_case, sha256_hex(&keyed));
    }

    #[test]
    fn an_unsafe_verdict_caches_too() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        // Seed a recorded-unsafe verdict for a pattern the cheap layers
        // pass (no dangerous construct, compiles): the cache answers it.
        cache.put("^(?:a|a?)+$", true, false, "over budget");
        let reloaded = ValidationCache::load(&path);
        let (safe, reason) = reloaded.get("^(?:a|a?)+$", true).expect("cached");
        assert!(!safe);
        assert_eq!(reason, "over budget");
        cleanup(&dir);
    }

    #[test]
    fn an_unpublishable_cache_keeps_the_memory_entry() {
        let (dir, path) = tempdir();
        // The cache path itself is a directory: the rename cannot land.
        std::fs::create_dir_all(&path).expect("cache path as dir");
        let cache = ValidationCache::load(&path);
        cache.put("some-pattern", true, true, "reason");
        // The in-memory entry stays answerable; nothing panics.
        assert_eq!(
            cache.get("some-pattern", true),
            Some((true, "reason".to_owned()))
        );
        cleanup(&dir);
    }

    #[test]
    fn the_debug_shape_names_the_path_and_outcome() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        let rendered = format!("{cache:?}");
        assert!(rendered.contains("validation-cache.json"));
        assert!(rendered.contains("Absent"));
        cleanup(&dir);
    }

    #[test]
    fn an_uncompilable_pattern_is_rejected_before_the_cache() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        // An unclosed group passes the dangerous-construct scan and
        // fails the compile check: rejected, nothing cached.
        let (safe, reason) = cache.validate_with_flags("(unclosed", true);
        assert!(!safe);
        assert!(!reason.is_empty());
        assert!(cache.get("(unclosed", true).is_none());
        cleanup(&dir);
    }

    #[test]
    fn a_repeat_validation_answers_from_the_cache() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        let (safe, _) = cache.validate_compat(r"^safe-\d+$");
        assert!(safe);
        // The second pass hits the recorded verdict without re-timing.
        let (safe, reason) = cache.validate_compat(r"^safe-\d+$");
        assert!(safe);
        assert!(!reason.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn case_sensitive_validation_uses_the_plain_flags_arm() {
        let (dir, path) = tempdir();
        let cache = ValidationCache::load(&path);
        // The not-ignorecase arm builds the default flags and compiles.
        let (safe, _) = cache.validate_with_flags(r"^safe-[a-z]+$", false);
        assert!(safe);
        assert!(cache.get(r"^safe-[a-z]+$", false).is_some());
        cleanup(&dir);
    }
}
