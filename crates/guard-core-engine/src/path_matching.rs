//! The `exclude_paths` matcher: the reference
//! `core/validation/path_matching.py`.
//!
//! A request path is normalized before it is compared, so an encoded or
//! dot-segmented spelling cannot slip past (or into) an exclusion:
//!
//! 1. percent-decode runs of `%XX` as UTF-8, up to four rounds; an invalid
//!    UTF-8 run, or a `%XX` still left after the fourth round, makes the
//!    path unmatchable (never excluded);
//! 2. fold `\` to `/`, drop empty and `.` segments, resolve `..` against
//!    the segments seen so far, and treat a `..;param` / `.;param` segment
//!    as its dot form.
//!
//! An exclusion matches the normalized path when it equals it or is a
//! `/`-bounded prefix of it (`/static` excludes `/static` and
//! `/static/app.js`, never `/staticx`); an exclusion of `/` matches every
//! path. Exclusions normalize the same way, and an exclusion that cannot
//! normalize is dropped.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::path_matching::PathExclusions;
//!
//! let exclusions = PathExclusions::new(["/static", "/docs"]);
//! assert!(exclusions.is_excluded("/static/app.js"));
//! assert!(exclusions.is_excluded("/static/../static/app.js"));
//! assert!(!exclusions.is_excluded("/static/../admin"));
//! assert!(!exclusions.is_excluded("/staticx"));
//! ```

/// The most percent-decode rounds the reference runs.
const MAX_DECODE_ROUNDS: usize = 4;

/// The value of one ASCII hex digit.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The byte a `%XX` escape at the start of `bytes` encodes.
fn escape_at(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [b'%', high, low, ..] => Some(hex_value(*high)? << 4 | hex_value(*low)?),
        _ => None,
    }
}

/// One round: every maximal run of `%XX` is decoded as UTF-8 (the
/// reference `(?:%[0-9A-Fa-f]{2})+` substitution). `None` when a run is not
/// valid UTF-8.
fn decode_percent_once(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if escape_at(&bytes[index..]).is_none() {
            // Copy one whole character (`%` and hex digits are ASCII, so a
            // non-escape position is always a char boundary).
            let ch = value[index..].chars().next()?;
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let mut run = Vec::new();
        while let Some(byte) = escape_at(&bytes[index..]) {
            run.push(byte);
            index += 3;
        }
        out.push_str(&String::from_utf8(run).ok()?);
    }
    Some(out)
}

/// Whether any `%XX` escape is left in `value`.
fn has_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    (0..bytes.len()).any(|index| escape_at(&bytes[index..]).is_some())
}

/// `_decode_percent_recursive`.
fn decode_percent_recursive(raw: &str) -> Option<String> {
    let mut decoded = raw.to_owned();
    for _ in 0..MAX_DECODE_ROUNDS {
        decoded = decode_percent_once(&decoded)?;
    }
    (!has_escape(&decoded)).then_some(decoded)
}

/// `_fold_dot_segment_params`: `..;x` and `.;x` fold to their dot form.
fn fold_dot_segment_params(segment: &str) -> &str {
    let base = segment.split(';').next().unwrap_or(segment);
    if base == "." || base == ".." {
        base
    } else {
        segment
    }
}

/// `_collapse_dot_segments`.
fn collapse_dot_segments(decoded: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for raw_segment in decoded.split(['/', '\\']) {
        match fold_dot_segment_params(raw_segment) {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    format!("/{}", segments.join("/"))
}

/// `normalize_url_path`: the comparable form of a raw request path, `None`
/// when it cannot be decoded safely.
#[must_use]
pub fn normalize_url_path(raw_path: &str) -> Option<String> {
    decode_percent_recursive(raw_path).map(|decoded| collapse_dot_segments(&decoded))
}

/// `normalize_exclude_paths`: the entries that normalize, in order.
#[must_use]
pub fn normalize_exclude_paths<I, S>(exclude_paths: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    exclude_paths
        .into_iter()
        .filter_map(|entry| normalize_url_path(entry.as_ref()))
        .collect()
}

/// `_is_subtree_or_equal`.
fn is_subtree_or_equal(path: &str, excluded: &str) -> bool {
    excluded == "/"
        || path == excluded
        || path
            .strip_prefix(excluded)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `path_matches_exclusions`: the already-normalized path against
/// already-normalized exclusions.
#[must_use]
pub fn path_matches_exclusions(normalized_path: &str, normalized_exclusions: &[String]) -> bool {
    normalized_exclusions
        .iter()
        .any(|excluded| is_subtree_or_equal(normalized_path, excluded))
}

/// `path_is_excluded`: normalize both sides and match.
#[must_use]
pub fn path_is_excluded<S: AsRef<str>>(url_path: &str, exclude_paths: &[S]) -> bool {
    normalize_url_path(url_path)
        .is_some_and(|path| path_matches_exclusions(&path, &normalize_exclude_paths(exclude_paths)))
}

/// The configured exclusions, normalized once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathExclusions {
    normalized: Vec<String>,
}

impl PathExclusions {
    /// Normalize `exclude_paths` once.
    pub fn new<I, S>(exclude_paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            normalized: normalize_exclude_paths(exclude_paths),
        }
    }

    /// The normalized exclusions.
    #[must_use]
    pub fn normalized(&self) -> &[String] {
        &self.normalized
    }

    /// Whether the raw request path is excluded.
    #[must_use]
    pub fn is_excluded(&self, url_path: &str) -> bool {
        normalize_url_path(url_path)
            .is_some_and(|path| path_matches_exclusions(&path, &self.normalized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULTS: [&str; 6] = [
        "/docs",
        "/redoc",
        "/openapi.json",
        "/openapi.yaml",
        "/favicon.ico",
        "/static",
    ];

    /// `(raw, normalized, excluded by the defaults, excluded by "/",
    /// excluded by ["/static/", "/a/./b/../c"], excluded by "/%73tatic")`,
    /// recorded from the reference `path_matching.py`.
    #[allow(clippy::type_complexity)]
    const REFERENCE: &[(&str, Option<&str>, bool, bool, bool, bool)] = &[
        (
            "/static/app.js",
            Some("/static/app.js"),
            true,
            true,
            true,
            true,
        ),
        ("/static", Some("/static"), true, true, true, true),
        ("/static/", Some("/static"), true, true, true, true),
        (
            "/static/../admin",
            Some("/admin"),
            false,
            true,
            false,
            false,
        ),
        ("/%2e%2e/admin", Some("/admin"), false, true, false, false),
        (
            "/static/%2e%2e/admin",
            Some("/admin"),
            false,
            true,
            false,
            false,
        ),
        ("/docs", Some("/docs"), true, true, false, false),
        ("/docs2", Some("/docs2"), false, true, false, false),
        ("/docsx/y", Some("/docsx/y"), false, true, false, false),
        (
            "/STATIC/app.js",
            Some("/STATIC/app.js"),
            false,
            true,
            false,
            false,
        ),
        ("/a//b/./c", Some("/a/b/c"), false, true, false, false),
        ("/a/b/..", Some("/a"), false, true, false, false),
        ("/a;x=1/../b", Some("/b"), false, true, false, false),
        ("/%252e%252e/x", Some("/x"), false, true, false, false),
        ("/%2525252e", Some("/"), false, true, false, false),
        ("/%ZZ", Some("/%ZZ"), false, true, false, false),
        ("/%ff", None, false, false, false, false),
        (
            "/%e2%82%ac/x",
            Some("/\u{20ac}/x"),
            false,
            true,
            false,
            false,
        ),
        ("/a\\b", Some("/a/b"), false, true, false, false),
        ("", Some("/"), false, true, false, false),
        ("/", Some("/"), false, true, false, false),
        ("//static//x", Some("/static/x"), true, true, true, true),
        (
            "/static;a=b/x",
            Some("/static;a=b/x"),
            false,
            true,
            false,
            false,
        ),
        ("/%00", Some("/\u{0}"), false, true, false, false),
        ("/%2F..%2Fadmin", Some("/admin"), false, true, false, false),
        ("/%252fstatic", Some("/static"), true, true, true, true),
        ("/x/..;/static/y", Some("/static/y"), true, true, true, true),
        ("/static/..;/y", Some("/y"), false, true, false, false),
        ("/%5c..%5cstatic", Some("/static"), true, true, true, true),
    ];

    #[test]
    fn normalization_and_matching_follow_the_reference_table() {
        for (raw, normalized, defaults, root, trailing, encoded) in REFERENCE {
            assert_eq!(
                normalize_url_path(raw).as_deref(),
                *normalized,
                "normalize {raw:?}"
            );
            assert_eq!(
                path_is_excluded(raw, &DEFAULTS),
                *defaults,
                "defaults {raw:?}"
            );
            assert_eq!(path_is_excluded(raw, &["/"]), *root, "root {raw:?}");
            assert_eq!(
                path_is_excluded(raw, &["/static/", "/a/./b/../c"]),
                *trailing,
                "trailing {raw:?}"
            );
            assert_eq!(
                path_is_excluded(raw, &["/%73tatic"]),
                *encoded,
                "encoded {raw:?}"
            );
        }
    }

    #[test]
    fn exclusions_normalize_and_drop_the_undecodable() {
        assert_eq!(
            normalize_exclude_paths(["/a/", "//b", "/%ff", "", "c/../d"]),
            ["/a", "/b", "/", "/d"]
        );
    }

    #[test]
    fn the_default_static_exclusion_covers_its_subtree() {
        let exclusions = PathExclusions::new(DEFAULTS);
        assert!(exclusions.is_excluded("/static/app.js"));
        assert!(!exclusions.is_excluded("/staticx/app.js"));
        assert!(!exclusions.is_excluded("/%ff"));
        assert_eq!(exclusions.normalized().len(), DEFAULTS.len());
    }
}
