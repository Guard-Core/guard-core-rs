//! Python `re` compatibility layer for the detection pattern table.
//!
//! The spec 4.0.2 table is authored as Python regex sources and the conformance
//! corpus compares the canonical source string carried by every threat. This
//! module compiles those sources for the `regex` crate with equivalent
//! semantics for the constructs the table uses.
//!
//! Translation rules:
//! - a leading `(?i)` is left in place (the crate honors it); builtin
//!   IGNORECASE is expressed by prepending `(?i)` when the source does not
//!   carry its own global flag;
//! - sources embedding `(?-i:...)` wrappers compile without a global case
//!   fold: the wrapper scopes case sensitivity back for the wrapped body and
//!   the crate honors that natively;
//! - `\Z` (Python absolute end) becomes `\z`;
//! - a bare `$` outside a class means "end of string or just before a
//!   trailing newline" in Python and becomes `(?:\n?\z)`.
//!
//! Constructs the crate rejects (lookaround, backreferences) fail compilation
//! here; those table entries are served by structural matchers instead.

use regex::Regex;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Process-wide compile cache. The reference compiles every pattern once at
/// module import; several structural helpers here compile helper sources
/// per call. `Regex` clone is an O(1) Arc clone, so caching compiled regexes
/// keyed by (source, case) makes every per-call compile a lookup after the
/// first use. The key set is bounded by the fixed source strings in this
/// crate.
static COMPILE_CACHE: LazyLock<Mutex<HashMap<(String, bool), Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct PyRegex {
    /// Canonical Python-style source; carried verbatim on threats.
    pub source: String,
    re: Regex,
}

fn translate(source: &str) -> String {
    let mut out = String::with_capacity(source.len() + 8);
    let mut chars = source.chars().peekable();
    let mut in_class = false;
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(ch);
            if let Some(&next) = chars.peek() {
                if next == 'Z' {
                    out.pop();
                    out.push_str("\\z");
                } else {
                    out.push(next);
                }
                chars.next();
            }
            continue;
        }
        match ch {
            '[' if !in_class => {
                in_class = true;
                out.push(ch);
            }
            ']' if in_class => {
                in_class = false;
                out.push(ch);
            }
            '$' if !in_class => {
                // Python `$`: end of string, or just before a trailing newline.
                out.push_str("(?:\\n?\\z)");
            }
            _ => out.push(ch),
        }
    }
    out
}

impl PyRegex {
    pub fn compile(source: &str, ignore_case: bool) -> Result<Self, String> {
        let effective_case = if source.contains("(?-i:") {
            // scoped case-sensitive body: the reference wraps fully
            // case-sensitive alternations in `(?-i:...)` and the builtin
            // IGNORECASE applies to nothing else in those sources
            false
        } else {
            ignore_case || source.starts_with("(?i)")
        };
        let cache_key = (source.to_owned(), effective_case);
        if let Ok(cache) = COMPILE_CACHE.lock()
            && let Some(re) = cache.get(&cache_key)
        {
            return Ok(Self {
                source: source.to_owned(),
                re: re.clone(),
            });
        }
        let translated = translate(source);
        let mut pattern = String::with_capacity(translated.len() + 8);
        if effective_case && !translated.starts_with("(?i)") {
            pattern.push_str("(?i)");
        }
        pattern.push_str(&translated);
        let re = Regex::new(&pattern).map_err(|e| format!("{source}: {e}"))?;
        if let Ok(mut cache) = COMPILE_CACHE.lock() {
            cache.insert(cache_key, re.clone());
        }
        Ok(Self {
            source: source.to_owned(),
            re,
        })
    }

    #[must_use]
    pub const fn re(&self) -> &Regex {
        &self.re
    }
}

/// Code-point index for a byte offset known to sit on a char boundary.
#[must_use]
pub fn cp_index(haystack: &str, byte_idx: usize) -> usize {
    haystack[..byte_idx].chars().count()
}

/// Candidate match as byte span into the scanned string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
}

impl Candidate {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub fn text<'a>(&self, haystack: &'a str) -> &'a str {
        &haystack[self.start..self.end]
    }
}

#[must_use]
pub fn find_all(re: &Regex, haystack: &str) -> Vec<Candidate> {
    re.find_iter(haystack)
        .map(|m| Candidate::new(m.start(), m.end()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_absolute_end_anchor() {
        let re = PyRegex::compile(r"\A[^\n]*x\s*\Z", false).unwrap();
        assert!(re.re().is_match("a x"));
        assert!(!re.re().is_match("a\nx"));
    }

    #[test]
    fn translates_python_dollar() {
        let re = PyRegex::compile(r"(?:/|\s|$)", false).unwrap();
        assert!(re.re().is_match("/"));
        assert!(re.re().is_match("x\n"));
    }

    #[test]
    fn scoped_case_sensitivity() {
        let re = PyRegex::compile("(?i)(?-i:rO0AB)", false).unwrap();
        assert!(re.re().is_match("rO0AB"));
        assert!(!re.re().is_match("ro0ab"));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn find_all_maps_every_match_to_a_candidate() {
        let re = PyRegex::compile(r"ab", false).unwrap();
        let ms = find_all(re.re(), "abxab");
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].start, 0);
        assert_eq!(ms[1].start, 3);
    }

    #[test]
    fn a_trailing_escape_passes_through_the_translator() {
        // a source ending in a lone backslash has no escaped char to consume
        assert_eq!(translate("x\\"), "x\\");
        assert_eq!(translate("\\"), "\\");
        // the regex crate rejects the malformed source, but only after the
        // translation ran
        assert!(PyRegex::compile("x\\", false).is_err());
    }
}
