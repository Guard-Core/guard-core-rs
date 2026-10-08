//! End-to-end body-scan detection tests: the adapter-side loop (extract body
//! scan values, scan each through the normal detect path, first threat wins)
//! driven over multipart, urlencoded, JSON, and fallback bodies.
//!
//! Detection cases mirror `tests/test_utils/test_binary_islands.py` (upstream
//! commit 5f399234) and the Go engine's `bodyscan_test.go` /
//! `binaryislands_test.go` (guard-core 4.0.4 parity).
//!
//! Fixture note: the Python tests compress seeded random bytes; the property
//! under test is a binary-dense payload, which the engine's string model here
//! builds directly from seeded pseudo-random bytes decoded lossily (ASCII
//! passes through, every other byte becomes U+FFFD). Assertions are on
//! detection outcomes, not on byte fixtures.

use guard_core_engine::detect::{self, DetectConfig, Threat};

const fn corpus_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
        max_scan_values: 512,
        max_scan_chars: 65_536,
        max_json_depth: 32,
    }
}

/// The loop every adapter runs over the extracted values: a forced registry
/// hit is an immediate threat, every other value goes through the normal
/// detect path, first threat wins.
fn scan_body(body: &str, content_type: &str, config: &DetectConfig) -> detect::DetectVerdict {
    for value in guard_core_engine::body_scan::extract_body_scan_values_with_exclusions(
        body,
        content_type,
        config,
        guard_core_engine::body_scan::ExcludedBodyFields::default(),
    ) {
        if value.forced_category.is_some() {
            return detect::DetectVerdict {
                is_threat: true,
                threat_score: 1.0,
                threats: Vec::new(),
                original_length: value.content.chars().count(),
                processed_length: value.content.chars().count(),
            };
        }
        let verdict = detect::detect(&value.content, &value.context, config);
        if verdict.is_threat {
            return verdict;
        }
    }
    detect::DetectVerdict {
        is_threat: false,
        threat_score: 0.0,
        threats: Vec::new(),
        original_length: 0,
        processed_length: 0,
    }
}

fn categories(verdict: &detect::DetectVerdict) -> Vec<&str> {
    verdict
        .threats
        .iter()
        .filter_map(|t| match t {
            Threat::Regex(r) => Some(r.category.as_str()),
            Threat::Semantic(_) => None,
        })
        .collect()
}

/// Deterministic pseudo-random bytes (xorshift64), the binary-dense payload
/// fixture.
fn noise_bytes(seed: u64, size: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state % 256) as u8);
    }
    out
}

/// The engine string model of raw bytes: lossy UTF-8 decode.
fn noise_text(seed: u64, size: usize) -> String {
    String::from_utf8_lossy(&noise_bytes(seed, size)).into_owned()
}

const MULTIPART: &str = "multipart/form-data; boundary=B0";
const SCRIPT: &str = "<script>alert(1)</script>";
const TAUTOLOGY: &str = "1 OR 1=1";

fn file_part_body(filename: &str, content: &str) -> String {
    format!(
        "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"{filename}\"\r\n\r\n{content}\r\n--B0--\r\n"
    )
}

// --- binary islands reduction (5f399234 detection cases) ---

#[test]
fn patterns_cannot_span_separate_islands() {
    let run_one = "choose one: SELECT";
    let run_two = "* FROM xYYYYYYYYYY";
    let payload = format!("{run_one}\u{0}{run_two}");
    let body = file_part_body("dump.bin", &format!("{}{payload}", noise_text(17, 4096)));
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(
        !verdict.is_threat,
        "SELECT/FROM split across islands must not detect: {:?}",
        categories(&verdict)
    );
}

#[test]
fn compressed_file_part_with_short_fragment_not_detected() {
    let payload = format!("{}\u{0}{TAUTOLOGY}\u{0}", noise_text(11, 4096));
    let body = file_part_body("installer.zip", &payload);
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(
        !verdict.is_threat,
        "short tautology inside a binary-dense upload must not detect: {:?}",
        categories(&verdict)
    );
}

#[test]
fn compressed_file_part_with_embedded_script_detected() {
    let payload = format!(
        "{}\u{0}{SCRIPT}\u{0}{}",
        noise_text(12, 4096),
        noise_text(13, 4096)
    );
    let body = file_part_body("page.html.bin", &payload);
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat, "the embedded script island must detect");
    assert!(categories(&verdict).contains(&"xss"));
}

#[test]
fn text_file_part_fully_scanned() {
    let payload = "-- benign --\r\nSELECT name FROM users; <script>alert(1)</script>\r\n";
    let body = file_part_body("notes.txt", payload);
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat, "a text upload must keep its full scan");
}

#[test]
fn lower_min_run_length_restores_short_fragment_detection() {
    let payload = format!("{}\u{0}{TAUTOLOGY}\u{0}", noise_text(14, 4096));
    let body = file_part_body("data.bin", &payload);
    let config = DetectConfig {
        binary_min_run_length: 4,
        ..corpus_config()
    };
    let verdict = scan_body(&body, MULTIPART, &config);
    assert!(
        verdict.is_threat,
        "min run length 4 must restore detection of the short fragment"
    );
}

#[test]
fn octet_stream_binary_body_still_fully_scanned() {
    let body = format!("{}\u{0}{TAUTOLOGY}\u{0}", noise_text(15, 4096));
    let verdict = scan_body(&body, "application/octet-stream", &corpus_config());
    assert!(
        verdict.is_threat,
        "the whole-body fallback scan keeps raw-body signature coverage"
    );
    assert!(
        categories(&verdict).contains(&"sqli"),
        "{:?}",
        categories(&verdict)
    );
}

#[test]
fn octet_stream_binary_body_with_embedded_script_detected() {
    let body = format!("{}\u{0}{SCRIPT}\u{0}", noise_text(16, 4096));
    let verdict = scan_body(&body, "application/octet-stream", &corpus_config());
    assert!(verdict.is_threat);
}

#[test]
fn short_text_body_keeps_full_scan() {
    let verdict = scan_body(TAUTOLOGY, "text/plain", &corpus_config());
    assert!(verdict.is_threat);
    assert!(categories(&verdict).contains(&"sqli"));
}

#[test]
fn mostly_text_body_with_single_null_keeps_full_scan() {
    let body = format!("benign body with {TAUTOLOGY}\u{0}");
    let verdict = scan_body(&body, "text/plain", &corpus_config());
    assert!(verdict.is_threat);
}

// --- urlencoded form bodies ---

#[test]
fn form_body_sqli_detected() {
    let verdict = scan_body(
        "q=1+OR+1%3D1",
        "application/x-www-form-urlencoded",
        &corpus_config(),
    );
    assert!(verdict.is_threat);
    assert!(categories(&verdict).contains(&"sqli"));
}

#[test]
fn form_field_value_detected_with_the_form_field_context() {
    // The value scans under `request_body:form_field`; the recon raw-view
    // scan (#21) must see the original value through it.
    let verdict = scan_body(
        "q=\\default",
        "application/x-www-form-urlencoded",
        &corpus_config(),
    );
    assert!(
        verdict.is_threat,
        "\\default in a form field must stay a recon probe"
    );
    assert!(categories(&verdict).contains(&"recon"));
}

#[test]
fn raw_span_sqli_comment_detected_after_clean_embedded_walk() {
    // The embedded JSON walk is clean, but the raw field text carries a
    // SQLi comment spanning the leaf boundary (`x/*` + `*/SELECT`). The
    // reference scans the walk leaves and then still scans the raw value
    // (`_check_embedded_json_if_applicable` followed by
    // `_check_value_enhanced`), so the extractor must hand the scan loop
    // both surfaces (parity with guard-core #122's body-surface vector
    // `body_raw_span_sqli_comment`).
    let verdict = scan_body(
        "q=%7B%22a%22%3A%22x%2F*%22%2C%22b%22%3A%22*%2FSELECT%22%7D",
        "application/x-www-form-urlencoded",
        &corpus_config(),
    );
    assert!(
        verdict.is_threat,
        "an attack spanning the raw text of a JSON-parsing field value must detect"
    );
    assert!(categories(&verdict).contains(&"sqli"));
}

// --- multipart parts ---

#[test]
fn empty_file_part_content_not_detected() {
    let body = file_part_body("empty.bin", "");
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(!verdict.is_threat);
}

#[test]
fn benign_upload_filename_and_content_not_detected() {
    let body = file_part_body("note.txt", "hello world");
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(!verdict.is_threat);
}

#[test]
fn malicious_upload_filename_detected() {
    for filename in ["shell.php.jpg", "evil.php%00.jpg"] {
        let body = file_part_body(filename, "harmless-bytes");
        let verdict = scan_body(&body, MULTIPART, &corpus_config());
        assert!(verdict.is_threat, "filename {filename} must detect");
        // The Go port compares the deduplicated category set.
        let set: Vec<&str> = categories(&verdict);
        assert!(
            set.iter().all(|c| *c == "file_upload"),
            "{filename}: {set:?}"
        );
    }
}

#[test]
fn malicious_upload_content_detected() {
    let cases = [
        ("<script>alert(1)</script>", "xss"),
        ("1' OR '1'='1", "sqli"),
    ];
    for (content, category) in cases {
        let body = file_part_body("note.txt", content);
        let verdict = scan_body(&body, MULTIPART, &corpus_config());
        assert!(verdict.is_threat, "content {content} must detect");
        assert_eq!(categories(&verdict), vec![category], "{content}");
    }
}

#[test]
fn base64_transfer_encoded_upload_content_detected() {
    // The engine scans the raw transfer-encoded text; the short-base64
    // additive view decodes it.
    let body = "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.b64\"\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\r\n--B0--\r\n";
    let verdict = scan_body(body, MULTIPART, &corpus_config());
    assert!(
        verdict.is_threat,
        "base64-encoded script payload must detect"
    );
}

#[test]
fn boundary_mismatch_falls_back_to_whole_body_blob_scan() {
    let raw = "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.b64\"\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\r\n--B0--\r\n";
    let verdict = scan_body(
        raw,
        "multipart/form-data; boundary=DOES-NOT-MATCH",
        &corpus_config(),
    );
    assert!(
        verdict.is_threat,
        "the blob fallback must still scan the body"
    );
}

#[test]
fn no_content_disposition_part_malicious_content_detected() {
    let body = "--B0\r\nContent-Type: text/plain\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n";
    let verdict = scan_body(body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat);
}

#[test]
fn text_field_without_filename_still_detected_via_payload() {
    let body = "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n";
    let verdict = scan_body(body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat);
}

#[test]
fn nested_multipart_mixed_file_part_is_detected() {
    let body = "--B0\r\nContent-Disposition: form-data; name=\"files\"\r\nContent-Type: multipart/mixed; boundary=INNER\r\n\r\n--INNER\r\nContent-Disposition: attachment; filename=\"shell.php.jpg\"\r\nContent-Type: application/octet-stream\r\n\r\npayload-bytes\r\n--INNER--\r\n--B0--\r\n";
    let verdict = scan_body(body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat, "nested multipart must detect");
    assert_eq!(categories(&verdict), vec!["file_upload"]);
}

// --- JSON bodies ---

#[test]
fn json_body_leaf_attack_detected() {
    let body = r#"{"system":"1 OR 1=1","meta":{"deep":"hello"}}"#;
    let verdict = scan_body(body, "application/json", &corpus_config());
    assert!(verdict.is_threat);
    assert!(categories(&verdict).contains(&"sqli"));
}

#[test]
fn json_body_mongo_operator_key_forces_a_nosql_hit() {
    let body = r#"{"$where": "1 OR 1=1"}"#;
    let verdict = scan_body(body, "application/json", &corpus_config());
    assert!(verdict.is_threat);
}

#[test]
fn embedded_json_leaf_attack_detected() {
    // The attack hides in a form field whose value is a JSON object; the
    // walk leaf scans with the :embedded_json context suffix.
    let body = r#"data={"a":"<script>alert(1)</script>"}"#;
    let verdict = scan_body(body, "application/x-www-form-urlencoded", &corpus_config());
    assert!(verdict.is_threat);
    assert!(categories(&verdict).contains(&"xss"));
}

// --- benign binary uploads stay quiet ---

#[test]
fn benign_binary_corpus_produces_no_threats() {
    // Random noise and the full byte range: island extraction keeps runs
    // short, and short printable runs must not pattern-match.
    let corpus: [(&str, String); 2] = [
        ("random.bin", noise_text(6, 4000)),
        (
            "blob.bin",
            String::from_utf8_lossy(
                &(0..256u16)
                    .cycle()
                    .take(20 * 256)
                    .map(|b| b as u8)
                    .collect::<Vec<u8>>(),
            )
            .into_owned(),
        ),
    ];
    for (filename, content) in corpus {
        let body = file_part_body(filename, &content);
        let verdict = scan_body(&body, MULTIPART, &corpus_config());
        assert!(
            !verdict.is_threat,
            "{filename} must not detect: {:?}",
            categories(&verdict)
        );
    }
}

#[test]
fn padded_webshell_detected_despite_binary_padding() {
    let payload = "<?php system($_GET['cmd']); ?>";
    let body = file_part_body(
        "shell.jpg",
        &format!("{payload}{}", noise_text(42, payload.len())),
    );
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat);
    assert_eq!(categories(&verdict), vec!["cmd_injection"]);
}

#[test]
fn pdf_fixture_style_script_island_detected() {
    let pdf = format!(
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nstream\n{}\n{SCRIPT}\nendstream\nendobj\n%%EOF",
        noise_text(4, 512)
    );
    let body = file_part_body("doc.pdf", &pdf);
    let verdict = scan_body(&body, MULTIPART, &corpus_config());
    assert!(verdict.is_threat, "the intact script island must detect");
}
