use std::num::NonZeroUsize;

use lru::LruCache;
use regex::Regex;

/// LRU cache for compiled regex patterns.
///
/// Capacity is clamped to 1..=5000. Patterns are compiled with
/// case-insensitive and multiline flags (`(?im)`).
pub struct PatternCache {
    cache: LruCache<String, Regex>,
}

impl PatternCache {
    /// Create a new cache. Capacity is clamped to 1..=5000.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(1, 5000);
        Self {
            cache: LruCache::new(NonZeroUsize::new(cap).expect("clamped to >= 1")),
        }
    }

    /// Retrieve from cache or compile and insert. LRU eviction on overflow.
    pub fn get_or_compile(&mut self, pattern: &str) -> Result<&Regex, regex::Error> {
        // single hash lookup via try_get_or_insert_mut (lru 0.17+)
        self.cache
            .try_get_or_insert_mut(pattern.to_owned(), || {
                Regex::new(&format!("(?im){pattern}"))
            })
            .map(|r| &*r)
    }

    /// Drop all cached entries.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Number of currently cached patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// `true` if no patterns are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Compile a one-shot pattern with case-insensitive + multiline flags.
pub fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!("(?im){pattern}"))
}

/// Check whether a pattern is safe from catastrophic backtracking with the
/// full reference safety chain (dangerous constructs, compile check,
/// structural detectors, probe synthesis, and the empirical cost arbiter).
///
/// The `regex` crate is linear-time, so this certifies the pattern source
/// the way the reference engine does: the reasons name the specific
/// finding and match the reference's human-readable prefixes.
///
/// Prefer [`crate::redos::validate_pattern_safety`] for the structured
/// verdict; this compat shim keeps the historic two-tuple shape.
pub fn validate_pattern_safety(pattern: &str) -> (bool, String) {
    crate::redos::validate_pattern_safety_compat(pattern)
}

/// Compile multiple patterns, skipping invalid ones. When `validate` is
/// true, patterns flagged by [`validate_pattern_safety`] are also skipped.
#[must_use]
pub fn batch_compile(patterns: &[&str], validate: bool) -> Vec<(String, Regex)> {
    patterns
        .iter()
        .filter_map(|&pat| {
            if validate && !validate_pattern_safety(pat).0 {
                return None;
            }
            compile(pat).ok().map(|re| (pat.to_owned(), re))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_basic_operations() {
        let mut cache = PatternCache::new(10);
        assert!(cache.is_empty());

        let re = cache.get_or_compile(r"\d+").unwrap();
        assert!(re.is_match("123"));
        assert_eq!(cache.len(), 1);

        // second lookup: same pattern, still 1 entry, LRU result consistent
        let r1 = cache.get_or_compile(r"\d+").unwrap().as_str().to_owned();
        let r2 = cache.get_or_compile(r"\d+").unwrap().as_str().to_owned();
        assert_eq!(r1, r2);
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_eviction_and_lru_order() {
        let mut cache = PatternCache::new(2);
        cache.get_or_compile("aaa").unwrap();
        cache.get_or_compile("bbb").unwrap();
        cache.get_or_compile("ccc").unwrap();
        assert_eq!(cache.len(), 2);

        // LRU: aaa was evicted; touch bbb then add new — ccc stays
        let mut cache = PatternCache::new(3);
        for i in 0..3 {
            cache.get_or_compile(&format!("pattern_{i}")).unwrap();
        }
        let _ = cache.get_or_compile("pattern_0").unwrap();
        cache.get_or_compile("pattern_new").unwrap();
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn cache_capacity_clamping() {
        assert_eq!(PatternCache::new(0).cache.cap().get(), 1);
        assert_eq!(PatternCache::new(99999).cache.cap().get(), 5000);
    }

    #[test]
    fn dangerous_patterns_detected() {
        for pat in [
            r"(.*)+",
            r"(.+)+",
            r"([a-z]*)+",
            r"([a-z]+)+",
            r".*.*",
            r".+.+",
        ] {
            let (safe, _) = validate_pattern_safety(pat);
            assert!(!safe, "should flag: {pat}");
        }
    }

    #[test]
    fn safe_patterns_pass() {
        let (safe, msg) = validate_pattern_safety(r"test\d+");
        assert!(safe);
        assert_eq!(msg, "Pattern appears safe");

        for pat in [r"<script[^>]*>", r"[a-zA-Z0-9]+"] {
            assert!(validate_pattern_safety(pat).0, "should pass: {pat}");
        }
    }

    #[test]
    fn bounded_cost_pattern_passes_at_the_configured_cap() {
        // At the default cap the zero-fill probes extrapolate over budget,
        // so callers cap the cost verdict at their content limit (the
        // corpus pins 10000 for this exact pattern).
        let verdict = crate::redos::validate_pattern_safety(
            r"\d{3}-\d{3}-\d{4}",
            &crate::redos::SafetyMode::CostVerdict {
                max_content_length: Some(10000),
            },
        );
        assert!(verdict.safe, "reason: {}", verdict.reason);

        let verdict = crate::redos::validate_pattern_safety(
            r"\d{3}-\d{3}-\d{4}",
            &crate::redos::SafetyMode::CostVerdict {
                max_content_length: None,
            },
        );
        assert!(!verdict.safe, "the default cap extrapolates over budget");
        assert_eq!(verdict.reason_class(), "over_budget");
    }

    #[test]
    fn compile_flags_and_errors() {
        // case-insensitive + multiline by default
        assert!(compile(r"select").unwrap().is_match("SELECT"));
        assert!(
            compile(r"^hello")
                .unwrap()
                .is_match("first line\nhello world")
        );
        // invalid pattern
        assert!(compile(r"invalid(pattern").is_err());
    }

    #[test]
    fn batch_compile_filters_invalid_and_dangerous() {
        let results = batch_compile(&[r"\d+", r"invalid(", r"[a-z]+"], false);
        assert_eq!(results.len(), 2);

        let results = batch_compile(&[r"\d+", r"(.*)+", r"[a-z]+"], true);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(p, _)| p != "(.*)+"));

        assert!(batch_compile(&[r"invalid(", r"[unclosed"], false).is_empty());
    }
}
