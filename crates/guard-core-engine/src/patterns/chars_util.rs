//! Character helpers shared by the structural matchers. The reference walks
//! Python strings by code point; these helpers provide the same semantics
//! over Rust byte offsets.

/// Python `\w` membership (Unicode word character or underscore).
#[must_use]
pub fn py_is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The character starting at (or spanning) `byte_idx`, if the index is a char
/// boundary.
#[must_use]
pub fn char_at(s: &str, byte_idx: usize) -> Option<(usize, char)> {
    s[byte_idx..].chars().next().map(|c| (byte_idx, c))
}

/// The character ending just before `byte_idx`, if `byte_idx` is a boundary.
#[must_use]
pub fn char_before(s: &str, byte_idx: usize) -> Option<(usize, char)> {
    s[..byte_idx].char_indices().next_back()
}

/// Walk to the start of the run of `pred` characters ending at `byte_idx`
/// (exclusive), like the reference's backward `while` loops.
#[must_use]
pub fn walk_back_while<F>(s: &str, mut byte_idx: usize, mut pred: F) -> usize
where
    F: FnMut(char) -> bool,
{
    while byte_idx > 0
        && let Some((i, c)) = char_before(s, byte_idx)
        && pred(c)
    {
        byte_idx = i;
    }
    byte_idx
}

/// Walk forward from `byte_idx` over `pred` characters, returning the end.
#[must_use]
pub fn walk_forward_while<F>(s: &str, mut byte_idx: usize, mut pred: F) -> usize
where
    F: FnMut(char) -> bool,
{
    while let Some((i, c)) = char_at(s, byte_idx)
        && pred(c)
    {
        byte_idx = i + c.len_utf8();
    }
    byte_idx
}

/// Python `str.find(sub, start, end)`.
///
/// `from` arrives as a byte offset that Python computes in code-point space
/// (callers do arithmetic like `pos + 1` or `barrier + 1 - len(opening)`).
/// A mid-char `from` snaps forward to the next boundary, which is exactly
/// where Python's next code point starts; an ASCII-delimiter match can never
/// begin inside a multi-byte char, so no match is skipped.
#[must_use]
pub fn str_find_from(s: &str, needle: &str, from: usize) -> Option<usize> {
    if from > s.len() {
        return None;
    }
    let mut from = from;
    while from < s.len() && !s.is_char_boundary(from) {
        from += 1;
    }
    s[from..].find(needle).map(|i| i + from)
}

/// Python `str.rfind(sub, start, end)`: last occurrence within `[start, end)`.
#[must_use]
pub fn str_rfind_in(s: &str, needle: &str, start: usize, end: usize) -> Option<usize> {
    let limit = end.min(s.len());
    if needle.is_empty() || start > limit {
        return None;
    }
    let capped = &s[..limit];
    capped[start..]
        .rfind(needle)
        .map(|i| i + start)
        .filter(|i| i + needle.len() <= limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_respect_char_boundaries() {
        let s = "a\u{00e9}b";
        assert_eq!(walk_back_while(s, s.len(), |c| c != '\u{00e9}'), 3);
        assert_eq!(walk_forward_while(s, 0, |c| c == 'a'), 1);
    }

    #[test]
    fn rfind_within_bounds() {
        assert_eq!(str_rfind_in("a.b.c", ".", 0, 3), Some(1));
        assert_eq!(str_rfind_in("a.b.c", ".", 2, 5), Some(3));
        assert_eq!(str_rfind_in("abc", "z", 0, 3), None);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn find_from_rejects_out_of_bounds_and_snaps_forward() {
        // past the end
        assert_eq!(str_find_from("abc", "b", 9), None);
        // a mid-char offset snaps to the next boundary
        let s = "a\u{00e9}b";
        assert_eq!(str_find_from(s, "b", 2), Some(3));
    }

    #[test]
    fn rfind_in_rejects_empty_needles_and_bad_bounds() {
        assert_eq!(str_rfind_in("abc", "", 0, 3), None);
        assert_eq!(str_rfind_in("abc", "b", 9, 9), None);
    }
}
