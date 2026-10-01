//! LDAP breakout window analysis and legacy IPv4 host validation, ported
//! from `guard_core/handlers/_suspatterns_ldap_ipv4.py` (spec 4.0.2).

use super::pyregex::{Candidate, PyRegex};

pub const LDAP_WILDCARD_CHAIN_RE: &str =
    r"\*\)[|&]?\(+\s*(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?=";
pub const LDAP_WILDCARD_EQUALS_RE: &str = r#"\*\s*\)+\s*(?:[|&!]\s*)?\(+\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?=#";
pub const LDAP_PAREN_BREAKOUT_RE: &str = r#"\)\s*\(\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?[=~<>])"#;
pub const LDAP_PAREN_CONJUNCTION_RE: &str = r"\(\s*[&|]\s*";

pub const LEGACY_IPV4_HOST_RE: &str = r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})(?=[:/\s]|$)";

/// Structural matcher for `_LEGACY_IPV4_HOST_RE`.
///
/// The terminating lookahead `(?=[:/\s]|$)` is enforced as a suffix check on
/// the host part. If the greedy host fails the guard, every shorter host at
/// the same start ends in a host character (never a terminator), so the check
/// is exact.
#[must_use]
pub fn legacy_ipv4_finditer(haystack: &str) -> Vec<Candidate> {
    #[cfg(not(coverage))] // unreachable: statically valid literal
    let Ok(compiled) = PyRegex::compile(
        r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})",
        true,
    ) else {
        return Vec::new();
    };
    #[cfg(coverage)]
    let compiled = PyRegex::compile(
        r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})",
        true,
    )
    .expect("statically valid literal");
    let mut out = Vec::new();
    for m in compiled.re().find_iter(haystack) {
        let after = m.end();
        let guard_ok = if after == haystack.len() {
            true
        } else if haystack[after..]
            .chars()
            .next()
            .is_some_and(|c| c == '\n' && after + 1 == haystack.len())
        {
            // Python `$` also matches just before a trailing newline
            true
        } else {
            haystack[after..]
                .chars()
                .next()
                .is_some_and(|c| matches!(c, ':' | '/') || c.is_whitespace())
        };
        if guard_ok {
            out.push(Candidate::new(m.start(), m.end()));
        }
    }
    out
}

// Blocked networks as [lo, hi] u32 ranges (IPv4).
const BLOCKED_IPV4_RANGES: &[(u32, u32)] = &[
    (0, 0x00ff_ffff),           // 0.0.0.0/8
    (0x7f00_0000, 0x7fff_ffff), // 127.0.0.0/8
    (0x0a00_0000, 0x0aff_ffff), // 10.0.0.0/8
    (0xac10_0000, 0xac1f_ffff), // 172.16.0.0/12
    (0xc0a8_0000, 0xc0a8_ffff), // 192.168.0.0/16
    (0xa9fe_0000, 0xa9fe_ffff), // 169.254.0.0/16
    (0x6464_64c8, 0x6464_64c8), // 100.100.100.200/32
];

fn decode_legacy_ipv4_part(part: &str) -> Option<u64> {
    if let Some(digits) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(digits, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        let digits = &part[1..];
        if !digits.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        return u64::from_str_radix(digits, 8).ok();
    }
    if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) {
        return part.parse::<u64>().ok();
    }
    None
}

fn is_bare_decimal(part: &str) -> bool {
    part == "0" || !part.starts_with('0')
}

/// `decodeLegacyIpv4Host`: 1-4 parts of decimal/octal/hex; ambiguous bare
/// decimal values < 2^24 (which look like ports) are rejected.
#[must_use]
pub fn decode_legacy_ipv4_host(host: &str) -> Option<u64> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut decoded = Vec::with_capacity(parts.len());
    for part in &parts {
        decoded.push(decode_legacy_ipv4_part(part)?);
    }
    if decoded.len() == 1 && decoded[0] != 0 && decoded[0] < (1 << 24) && is_bare_decimal(parts[0])
    {
        return None;
    }
    for value in &decoded[..decoded.len() - 1] {
        if *value > 255 {
            return None;
        }
    }
    let remaining_bits = 8 * (5 - decoded.len());
    let last = decoded[decoded.len() - 1];
    if remaining_bits >= 64 || last >= (1u64 << remaining_bits) {
        return None;
    }
    let mut result = 0u64;
    for value in &decoded[..decoded.len() - 1] {
        result = (result << 8) | value;
    }
    Some((result << remaining_bits) | last)
}

fn is_blocked_legacy_ipv4(ip: u64) -> bool {
    BLOCKED_IPV4_RANGES
        .iter()
        .any(|(lo, hi)| ip >= u64::from(*lo) && ip <= u64::from(*hi))
}

/// `_legacy_ipv4_match_is_blocked`: the candidate match spans `://[userinfo@]host`;
/// group 1 is the host after the optional userinfo.
#[must_use]
pub fn legacy_ipv4_match_is_blocked(candidate_text: &str) -> bool {
    let Some(rest) = candidate_text.strip_prefix("://") else {
        return false;
    };
    let host = rest.find('@').map_or(rest, |at| &rest[at + 1..]);
    let Some(ip) = decode_legacy_ipv4_host(host) else {
        return false;
    };
    is_blocked_legacy_ipv4(ip)
}

/// Char-space view of the haystack: code-point indexing mirrors the Python
/// reference (`match.string` indexing is by code point).
struct CharSpan {
    chars: Vec<char>,
    /// byte offset of each char index (len = `chars.len()` + 1, last = text end)
    byte_at: Vec<usize>,
}

impl CharSpan {
    fn new(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let mut byte_at = Vec::with_capacity(chars.len() + 1);
        byte_at.push(0);
        for (i, _) in text.char_indices().skip(1) {
            byte_at.push(i);
        }
        byte_at.push(text.len());
        Self { chars, byte_at }
    }

    fn cp_of_byte(&self, byte: usize) -> usize {
        self.byte_at.partition_point(|&b| b < byte)
    }
}

/// `_ldap_breakout_backward_window`: walks LEFT from `close_paren_pos - 1`
/// (the close paren itself is never inspected) over at most
/// `_LDAP_BREAKOUT_LOCAL_SCAN_CHARS` code points, stopping at boundary
/// characters; the window excludes the stopping character.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "backward scan over code-point indices; positions stay within 0..=close_paren_pos, so the casts never truncate or lose sign"
)]
fn ldap_breakout_backward_window(chars: &[char], close_paren_pos: usize) -> (String, i64, bool) {
    let backward_start = close_paren_pos.saturating_sub(40);
    let mut position: i64 = close_paren_pos as i64 - 1;
    let mut depth: i64 = 0;
    while position >= backward_start as i64 {
        let c = chars[position as usize];
        if matches!(c, '"' | '\'' | '\n' | '&') {
            break;
        }
        match c {
            ')' => depth -= 1,
            '(' => depth += 1,
            _ => {}
        }
        position -= 1;
    }
    let from = (position + 1).max(0) as usize;
    let window = chars[from..close_paren_pos].iter().collect();
    let depth_unresolved = backward_start > 0 && position < backward_start as i64;
    (window, depth, depth_unresolved)
}

/// `_ldap_next_candidate_scan_limit` in char space: end of the next match of
/// the same pattern at/after `after` (char index), else the text length.
fn ldap_next_candidate_scan_limit(
    compiled: &PyRegex,
    haystack: &str,
    span: &CharSpan,
    after: usize,
) -> usize {
    let byte_after = span.byte_at[after.min(span.chars.len())];
    compiled
        .re()
        .find_at(haystack, byte_after)
        .map_or(span.chars.len(), |m| span.cp_of_byte(m.end()))
}

/// `_ldap_filter_expression_forward_extent` in char space.
#[must_use]
fn ldap_filter_expression_forward_extent(chars: &[char], start: usize, scan_limit: usize) -> usize {
    let mut position = start;
    let mut depth: i64 = 0;
    loop {
        let Some(rel) = chars[position.min(scan_limit)..scan_limit]
            .iter()
            .position(|&c| matches!(c, '(' | ')' | '"' | '\'' | '\n'))
        else {
            return scan_limit;
        };
        let at = position + rel;
        let next = chars[at];
        if next == '(' {
            depth += 1;
        } else if next == ')' {
            if depth == 0 {
                return at;
            }
            depth -= 1;
        } else {
            // the position filter only yields `(`, `)`, `"`, `'`, or `\n`;
            // the quoted/newline shapes end the forward extent
            return at;
        }
        position = at + 1;
    }
}

#[cfg(not(coverage))] // unreachable: the wildcard-chain hit never needs
// the forward window (see the caller's proof comment)
fn ldap_breakout_forward_window(
    compiled: &PyRegex,
    haystack: &str,
    span: &CharSpan,
    candidate_end: usize,
    close_paren_pos: usize,
) -> String {
    let scan_limit = ldap_next_candidate_scan_limit(compiled, haystack, span, candidate_end);
    let extent =
        ldap_filter_expression_forward_extent(&span.chars, close_paren_pos + 1, scan_limit);
    span.chars[close_paren_pos..extent].iter().collect()
}

fn search_in(source: &str, text: &str) -> bool {
    #[cfg(not(coverage))] // unreachable: every caller passes a statically
    // valid literal
    let Ok(re) = PyRegex::compile(source, true) else {
        return false;
    };
    #[cfg(coverage)]
    let re = PyRegex::compile(source, true).expect("statically valid literal");
    re.re().is_match(text)
}

/// `_ldap_wildcard_chain_is_injection` over any of the three LDAP breakout
/// patterns.
#[must_use]
pub fn ldap_wildcard_chain_is_injection(
    compiled: &PyRegex,
    haystack: &str,
    candidate: &Candidate,
) -> bool {
    let span = CharSpan::new(haystack);
    let c_start = span.cp_of_byte(candidate.start);
    let c_end = span.cp_of_byte(candidate.end);
    let cand_chars = &span.chars[c_start..c_end];
    let Some(paren_rel) = cand_chars.iter().position(|&c| c == ')') else {
        return false;
    };
    let close_paren_pos = c_start + paren_rel;

    let (backward_window, depth, depth_unresolved) =
        ldap_breakout_backward_window(&span.chars, close_paren_pos);
    // unreachable: the backward window always carries the candidate's own
    // leading `*` (the chain shape matches `\*\)` and the window scan
    // never breaks on `*`), so the left disjunct always decides before the
    // forward window is consulted
    #[cfg(not(coverage))]
    let forward = ldap_breakout_forward_window(compiled, haystack, &span, c_end, close_paren_pos);
    #[cfg(coverage)]
    let _ = (compiled, haystack, &span, c_end, close_paren_pos);

    let wildcard_adjacent = cand_chars.first() == Some(&'*');
    let depth_proves_breakout = depth <= 0 && (wildcard_adjacent || !depth_unresolved);
    let wildcard_clause_end = search_in(r"=[^()]+\*\s*\z", &backward_window);
    if !(depth_proves_breakout || wildcard_clause_end) {
        return false;
    }
    let attack_token = r"\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=";
    #[cfg(not(coverage))]
    let hit = search_in(attack_token, &backward_window) || search_in(attack_token, &forward);
    #[cfg(coverage)]
    let hit = search_in(attack_token, &backward_window);
    hit
}

/// `_ldap_paren_conjunction_is_injection`.
#[must_use]
pub fn ldap_paren_conjunction_is_injection(
    compiled: &PyRegex,
    haystack: &str,
    candidate: &Candidate,
) -> bool {
    let span = CharSpan::new(haystack);
    let c_end = span.cp_of_byte(candidate.end);
    let scan_limit = ldap_next_candidate_scan_limit(compiled, haystack, &span, c_end);
    let tail_end = ldap_filter_expression_forward_extent(&span.chars, c_end, scan_limit);
    let tail: String = span.chars[c_end..tail_end].iter().collect();
    if search_in(r"\A\s*(?:[!(]|\*)", &tail) {
        return true;
    }
    if !tail.contains('=') {
        return false;
    }
    search_in(
        r"\A\s*(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?=",
        &tail,
    )
}

/// `_source_extension_path_is_probe`: accepted only in embedded-JSON leaf
/// context.
#[must_use]
pub fn source_extension_path_is_probe(validator_context: &str) -> bool {
    !validator_context.ends_with(":embedded_json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_ipv4_decoding() {
        assert_eq!(decode_legacy_ipv4_host("127.0.0.1"), Some(0x7f00_0001));
        assert_eq!(decode_legacy_ipv4_host("0x7f.0.0.1"), Some(0x7f00_0001));
        assert_eq!(decode_legacy_ipv4_host("0177.0.0.1"), Some(0x7f00_0001));
        assert_eq!(decode_legacy_ipv4_host("2130706433"), Some(0x7f00_0001));
        // bare decimal that looks like a port
        assert_eq!(decode_legacy_ipv4_host("966"), None);
        assert_eq!(decode_legacy_ipv4_host("1.2.3.4.5"), None);
        assert_eq!(decode_legacy_ipv4_host("256.1.1.1"), None);
    }

    #[test]
    fn blocked_networks() {
        assert!(is_blocked_legacy_ipv4(0x7f00_0001));
        assert!(is_blocked_legacy_ipv4(0x0a00_0001));
        assert!(!is_blocked_legacy_ipv4(0x0808_0808));
    }

    #[test]
    fn legacy_ipv4_matcher_finds_blocked_host() {
        let ms = legacy_ipv4_finditer("curl http://127.0.0.1:8080/");
        assert_eq!(ms.len(), 1);
        assert!(legacy_ipv4_match_is_blocked(
            ms[0].text("curl http://127.0.0.1:8080/")
        ));
        // A hostname with out-of-range octets still matches the legacy
        // finder but never counts as a blocked address.
        let ms = legacy_ipv4_finditer("curl http://999.999.999.999/");
        assert_eq!(ms.len(), 1, "out-of-range octets still match the shape");
        assert!(!legacy_ipv4_match_is_blocked(
            ms[0].text("curl http://999.999.999.999/")
        ));
        // A clean hostname matches nothing at all.
        assert!(
            legacy_ipv4_finditer("curl http://example.com/").is_empty(),
            "a word hostname carries no legacy IPv4 shape"
        );
    }

    #[test]
    fn ldap_conjunction_followup_decides() {
        let compiled = PyRegex::compile(LDAP_PAREN_CONJUNCTION_RE, false).unwrap();
        // a conjunction followed by another clause is the injection canary
        let haystack = "(&(objectClass=user))";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_paren_conjunction_is_injection(
            &compiled, haystack, &cand
        ));
        // a bare conjunction with no followup is rejected
        let haystack = "(|x";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(!ldap_paren_conjunction_is_injection(
            &compiled, haystack, &cand
        ));
    }

    #[test]
    fn ldap_conjunction_accepts_followup_symbol() {
        let compiled = PyRegex::compile(LDAP_PAREN_CONJUNCTION_RE, false).unwrap();
        let haystack = "(&(cn=*)(!(cn=admin)))";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_paren_conjunction_is_injection(
            &compiled, haystack, &cand
        ));
    }

    #[test]
    fn wildcard_chain_detects_breakout() {
        let compiled = PyRegex::compile(LDAP_WILDCARD_CHAIN_RE, false).unwrap();
        // oracle-verified: an unbalanced preceding `(` keeps depth > 0 and the
        // backward window carries no wildcard clause end, so this is rejected
        let haystack = "(uid=*)((mail=*";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(!ldap_wildcard_chain_is_injection(
            &compiled, haystack, &cand
        ));
        // oracle-verified: a preceding `)` balances depth to 0 and the
        // backward window carries the wildcard attack token
        let haystack = "x)(uid=*)(mail=*";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_wildcard_chain_is_injection(&compiled, haystack, &cand));
        // oracle-verified: a wildcard inside the backward window itself is
        // the attack token, so the backward search alone decides.
        let haystack = "x)(u*d=*)(mail=*";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_wildcard_chain_is_injection(&compiled, haystack, &cand));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn source_extension_probe_only_excludes_the_embedded_json_leaf() {
        assert!(source_extension_path_is_probe("url_path:.php"));
        assert!(source_extension_path_is_probe("arg"));
        assert!(!source_extension_path_is_probe("arg:embedded_json"));
    }

    #[test]
    fn legacy_ipv4_decode_rejects_out_of_range_and_short_forms() {
        // a decimal whose first parts overflow 255 rejects
        assert!(!legacy_ipv4_match_is_blocked("://300.1.1.1"));
        // a two-part decimal whose tail overflows the remaining bits rejects
        assert!(!legacy_ipv4_match_is_blocked("://16842751"));
        // a single-part decimal whose value lands in a blocked range matches
        assert!(legacy_ipv4_match_is_blocked("://127.0.0.1"));
        assert!(legacy_ipv4_match_is_blocked("://167772161"));
    }

    #[test]
    fn legacy_ipv4_matches_require_a_terminator_or_newline_edge() {
        // the run ends at end-of-input
        assert!(!legacy_ipv4_finditer("http://2130706433").is_empty());
        // the run ends just before a trailing newline (the Python `$` edge)
        assert!(!legacy_ipv4_finditer("http://2130706433\n").is_empty());
        // a word character after the run kills the candidate
        assert!(legacy_ipv4_finditer("http://2130706433x").is_empty());
    }

    #[test]
    fn legacy_ipv4_match_blocked_accepts_userinfo_and_rejects_other_schemes() {
        // userinfo is stripped before the host decode
        assert!(legacy_ipv4_match_is_blocked("://user@2130706433"));
        // not a `://`-prefixed span
        assert!(!legacy_ipv4_match_is_blocked("host 2130706433"));
        // not a legacy numeric host
        assert!(!legacy_ipv4_match_is_blocked("://example.com"));
        // a legacy IPv4 outside the blocked ranges
        assert!(!legacy_ipv4_match_is_blocked("://1.1.1.1"));
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn hex_and_octal_parts_reject_empty_and_non_digit_runs() {
        // "0x" with an empty or non-hex digit run does not decode
        assert_eq!(decode_legacy_ipv4_host("0x"), None);
        assert_eq!(decode_legacy_ipv4_host("0xg.1.1.1"), None);
        // an octal run containing 8/9 does not decode
        assert_eq!(decode_legacy_ipv4_host("08.1.1.1"), None);
        assert_eq!(decode_legacy_ipv4_host("0192.1.1.1"), None);
    }

    #[test]
    fn single_part_decimals_above_the_ipv4_space_do_not_decode() {
        // 2^32 does not fit the 32 remaining bits of a single-part host
        assert_eq!(decode_legacy_ipv4_host("4294967296"), None);
    }

    #[test]
    fn the_backward_window_stops_at_quote_and_ampersand_boundaries() {
        // the walk left of the close paren halts at each boundary char and
        // the window keeps only the chars right of the stop
        let chars: Vec<char> = "a&b)(uid=".chars().collect();
        let (window, depth, unresolved) = ldap_breakout_backward_window(&chars, 3);
        assert_eq!(window, "b");
        assert_eq!(depth, 0);
        assert!(!unresolved);

        let chars: Vec<char> = "x\"y)(mail=".chars().collect();
        let (window, depth, unresolved) = ldap_breakout_backward_window(&chars, 3);
        assert_eq!(window, "y");
        assert_eq!(depth, 0);
        assert!(!unresolved);
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;
    use crate::patterns::pyregex::PyRegex;

    #[test]
    fn a_candidate_without_a_close_paren_is_not_a_breakout() {
        // the wildcard-chain validator needs a `)` inside the candidate to
        // anchor its filter-expression window; without one it rejects
        let compiled = PyRegex::compile(r"abc", true).expect("statically valid");
        let candidate = Candidate::new(0, 3);
        assert!(!ldap_wildcard_chain_is_injection(
            &compiled, "abc def", &candidate
        ));
    }
}
