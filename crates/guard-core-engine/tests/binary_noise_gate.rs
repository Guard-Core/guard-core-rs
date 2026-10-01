// The suite's assert-on-emptiness idiom is pervasive here; clippy 1.99's new
// assert_is_empty lint (assert_eq!(x, []) for the failure printout) is allowed
// file-wide rather than rewriting the assertion surface in a release train.
#![allow(unknown_lints)] // the lint name below postdates the 1.92 MSRV clippy
#![allow(clippy::assert_is_empty)]

//! Honesty tests for the binary-body noise gate (guard-core 4.0.3, upstream
//! commit `436d6f72`, ported from
//! `tests/test_sus_patterns/test_pattern_binary_noise_gate.py`).
//!
//! Positive side: real binary uploads (random noise, zip archives, control
//! byte runs) must NOT be blocked. Negative side: attacks hidden inside
//! binary padding MUST still be caught, and pure/accented/non-Latin text
//! behavior is unchanged.
//!
//! String-model note: the Python reference decodes request bytes with
//! `latin-1` or `utf-8 ... errors="surrogateescape"`, so undecodable bytes
//! surface as surrogateescape code points (U+DC80..U+DCFF, artifact class).
//! The Rust engine scans `&str`, so the same payloads are reconstructed
//! lossily (invalid bytes become U+FFFD, also an artifact class); the gate
//! fires on the same real-world byte sequences because both representations
//! count the same bad bytes toward the density window.

use guard_core_engine::detect::{self, DetectConfig, Threat};
use guard_core_engine::patterns::{self, table};
use guard_core_engine::preprocessor;

const MULTIPART_FIELD_CONTEXT: &str = "request_body:multipart_field";

const fn corpus_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

/// MT19937 core, seeded and read exactly like the `CPython` `random` module:
/// `random.Random(seed).randrange(256)` draws one 32-bit word per byte and
/// shifts right by 24, so the engine test can reproduce the reference test's
/// payload bytes bit-for-bit.
struct Mt19937 {
    state: [u32; 624],
    index: usize,
}

impl Mt19937 {
    /// `CPython` `random.seed(int)` seeding: `init_by_array` over the 32-bit
    /// words of the absolute seed value (single word for the seeds used here).
    fn new(seed: u32) -> Self {
        let mut state = [0u32; 624];
        state[0] = 19_650_218;
        for i in 1..624 {
            let prev = state[i - 1] ^ (state[i - 1] >> 30);
            state[i] = 1_812_433_253u32
                .wrapping_mul(prev)
                .wrapping_add(u32::try_from(i).unwrap_or(u32::MAX));
        }
        let key = [seed];
        let mut i = 1usize;
        let mut j = 0usize;
        for _ in 0..624.max(key.len()) {
            let prev = state[i - 1] ^ (state[i - 1] >> 30);
            state[i] = (state[i] ^ prev.wrapping_mul(1_664_525))
                .wrapping_add(key[j])
                .wrapping_add(u32::try_from(j).unwrap_or(u32::MAX));
            i += 1;
            j += 1;
            if i >= 624 {
                state[0] = state[623];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
        }
        for _ in 0..623 {
            let prev = state[i - 1] ^ (state[i - 1] >> 30);
            state[i] = (state[i] ^ prev.wrapping_mul(1_566_083_941))
                .wrapping_sub(u32::try_from(i).unwrap_or(u32::MAX));
            i += 1;
            if i >= 624 {
                state[0] = state[623];
                i = 1;
            }
        }
        state[0] = 0x8000_0000;
        Self { state, index: 624 }
    }

    fn next_word(&mut self) -> u32 {
        if self.index >= 624 {
            for i in 0..624 {
                let y = (self.state[i] & 0x8000_0000) | (self.state[(i + 1) % 624] & 0x7FFF_FFFF);
                let mut next = self.state[(i + 397) % 624] ^ (y >> 1);
                if y & 1 != 0 {
                    next ^= 0x9908_B0DF;
                }
                self.state[i] = next;
            }
            self.index = 0;
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C_5680;
        y ^= (y << 15) & 0xEFC6_0000;
        y ^= y >> 18;
        y
    }
}

/// Byte-identical twin of the reference test's `_noise_bytes(seed)` (Python
/// `random.Random(seed).randrange(256)` over 262144 draws). `randrange(256)`
/// is `_randbelow(256)`: `256.bit_length()` is 9, so each draw is
/// `getrandbits(9)` (a 32-bit word shifted right by 23) rejected while it
/// exceeds 255.
fn noise_bytes(seed: u64) -> Vec<u8> {
    let mut rng = Mt19937::new(u32::try_from(seed).unwrap_or(u32::MAX));
    (0..262_144)
        .map(|_| {
            loop {
                let draw = rng.next_word() >> 23;
                if draw < 256 {
                    return u8::try_from(draw).unwrap_or(0);
                }
            }
        })
        .collect()
}

/// The reference `latin-1` decoding: one char per byte, `U+0000..=U+00FF`.
fn decode_latin1(raw: &[u8]) -> String {
    raw.iter().map(|b| char::from(*b)).collect()
}

/// The reference `utf-8 ... errors="surrogateescape"` decoding, mapped into
/// the engine's `&str` world: valid UTF-8 sequences decode as-is, invalid
/// bytes become U+FFFD (the engine's artifact representation for bad bytes).
fn decode_lossy(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Minimal single-entry stored (uncompressed) ZIP archive, the same payload
/// class as the reference test's `zipfile.ZipFile` upload.
fn zip_bytes(seed: u64) -> Vec<u8> {
    let payload = &noise_bytes(seed)[..50_000];
    let name = b"attachment.bin";
    let crc = crc32(payload);
    let size = u32::try_from(payload.len()).expect("payload fits u32");

    let mut out = Vec::new();
    // local file header
    out.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    // stored payload
    out.extend_from_slice(payload);
    let header_offset = u32::try_from(out.len()).unwrap_or(0).wrapping_sub(size);
    let cd_offset_at = out.len();
    // central directory header
    out.extend_from_slice(&[
        0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    out.extend_from_slice(&header_offset.to_le_bytes());
    out.extend_from_slice(name);
    // end of central directory
    let cd_size = u32::try_from(out.len() - cd_offset_at).unwrap_or(0);
    out.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn detect_str(payload: &str) -> detect::DetectVerdict {
    detect::detect(payload, MULTIPART_FIELD_CONTEXT, &corpus_config())
}

const NOISE_SEEDS: [u64; 5] = [1, 2, 3, 42, 1337];

#[test]
fn random_binary_noise_produces_zero_threats() {
    for seed in NOISE_SEEDS {
        let latin1 = decode_latin1(&noise_bytes(seed));
        let verdict = detect_str(&latin1);
        assert!(
            !verdict.is_threat,
            "seed {seed}: latin-1 noise flagged: {:?}",
            verdict.threats
        );
        let lossy = decode_lossy(&noise_bytes(seed));
        let verdict = detect_str(&lossy);
        assert!(
            !verdict.is_threat,
            "seed {seed}: lossy-decoded noise flagged: {:?}",
            verdict.threats
        );
    }
}

#[test]
fn zip_upload_produces_zero_threats() {
    let bytes = zip_bytes(11);
    let verdict = detect_str(&decode_lossy(&bytes));
    assert!(
        !verdict.is_threat,
        "zip upload flagged: {:?}",
        verdict.threats
    );
}

#[test]
fn real_payloads_still_detected() {
    for payload in [
        "`rm -rf /`",
        "$(cat /etc/passwd)",
        "c'a't config.ini",
        "'; DROP TABLE users;--",
        "../../../etc/passwd",
    ] {
        let verdict = detect_str(payload);
        assert!(verdict.is_threat, "payload missed: {payload}");
        assert!(!verdict.threats.is_empty());
    }
}

#[test]
fn non_latin_text_without_payload_not_flagged() {
    for sample in [
        "Caf\u{00e9} r\u{00e9}sum\u{00e9} na\u{00ef}ve d\u{00e9}cor s\u{00e9}lection",
        "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c6}\u{30ad}\u{30b9}\u{30c8}\u{3067}\u{3059}\u{3002}\u{4e2d}\u{56fd}\u{8a9e}\u{8207}\u{7e41}\u{9ad4}\u{5b57}\u{3002}\u{d55c}\u{ad6d}\u{c5b4} \u{d14d}\u{c2a4}\u{d2b8}",
        "\u{43a}\u{438}\u{440}\u{438}\u{43b}\u{43b}\u{438}\u{446}\u{430} \u{438} \u{440}\u{443}\u{441}\u{441}\u{43a}\u{438}\u{439} \u{442}\u{435}\u{43a}\u{441}\u{442}",
    ] {
        let verdict = detect_str(sample);
        assert!(!verdict.is_threat, "text flagged: {sample}");
        assert!(verdict.threats.is_empty());
    }
}

#[test]
fn non_latin_text_with_embedded_backtick_still_detected() {
    for sample in [
        "Caf\u{00e9} r\u{00e9}sum\u{00e9} na\u{00ef}ve d\u{00e9}cor s\u{00e9}lection",
        "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c6}\u{30ad}\u{30b9}\u{30c8}\u{3067}\u{3059}\u{3002}\u{4e2d}\u{56fd}\u{8a9e}\u{8207}\u{7e41}\u{9ad4}\u{5b57}\u{3002}\u{d55c}\u{ad6d}\u{c5b4} \u{d14d}\u{c2a4}\u{d2b8}",
        "\u{43a}\u{438}\u{440}\u{438}\u{43b}\u{43b}\u{438}\u{446}\u{430} \u{438} \u{440}\u{443}\u{441}\u{441}\u{43a}\u{438}\u{439} \u{442}\u{435}\u{43a}\u{441}\u{442}",
    ] {
        let payload = format!("{sample}; `rm -rf /`");
        let verdict = detect_str(&payload);
        assert!(verdict.is_threat, "embedded backtick missed: {payload}");
        assert!(!verdict.threats.is_empty());
    }
}

#[test]
fn payload_near_string_start_still_detected() {
    let verdict = detect_str("../../../etc/passwd and more prose here");
    assert!(verdict.is_threat);
}

#[test]
fn payload_near_string_end_still_detected() {
    let payload = format!("{}../../../etc/passwd", "prose ".repeat(30));
    let verdict = detect_str(&payload);
    assert!(verdict.is_threat);
}

#[test]
fn short_value_below_window_margin_still_detected() {
    let verdict = detect_str("caf\u{00e9} '; DELETE FROM users;--");
    assert!(verdict.is_threat);
}

#[test]
fn control_char_only_value_not_flagged() {
    let nulls: String = "\u{0}".repeat(500);
    let controls: String = (1u32..32)
        .map(|cp| char::from_u32(cp).unwrap_or('\u{1}'))
        .collect::<String>()
        .repeat(40);
    let dels: String = "\u{7f}".repeat(300);
    for control_only in [nulls, controls, dels] {
        let verdict = detect_str(&control_only);
        assert!(
            !verdict.is_threat,
            "control-only value flagged: {:?}",
            verdict.threats
        );
        assert!(verdict.threats.is_empty());
    }
}

#[test]
fn payload_fragment_buried_in_binary_noise_not_flagged() {
    let traversal = format!(
        "{}..{}{}{}{}/{}",
        "\u{85}".repeat(200),
        "\u{9f}",
        "\u{9e}",
        "\u{9d}",
        "\u{9c}",
        "\u{87}".repeat(200)
    );
    let verdict = detect_str(&traversal);
    assert!(
        !verdict.is_threat,
        "buried traversal fragment flagged: {:?}",
        verdict.threats
    );

    let dollar = format!(
        "{}$(cat /etc/passwd){}",
        "\u{85}".repeat(200),
        "\u{87}".repeat(200)
    );
    let verdict = detect_str(&dollar);
    assert!(
        !verdict.is_threat,
        "buried dollar fragment flagged: {:?}",
        verdict.threats
    );
}

#[test]
fn binary_noise_scan_completes_under_five_seconds() {
    let started = std::time::Instant::now();
    let latin1 = decode_latin1(&noise_bytes(3));
    let verdict = detect_str(&latin1);
    let elapsed = started.elapsed();
    assert!(!verdict.is_threat);
    assert!(elapsed.as_secs_f64() < 5.0, "noise scan took {elapsed:?}");
}

/// The gate must be load-bearing: with the density prefix zeroed (gate
/// disabled), every noise-prone pattern source actually fires on binary
/// noise. Mirrors the reference `test_noise_prone_registry_is_truthful`;
/// the MT19937 generator reproduces the reference payloads byte-for-byte.
#[test]
fn noise_prone_registry_is_truthful() {
    // Sources whose shape requires a specific trigram/terminator run (e.g. the
    // SQLi comment terminator "'\n--") cannot be expected to occur in pure
    // random noise; their registry membership and suppression are covered by
    // the dedicated tests below (upstream commit f5d53ca5).
    const TRIGRAM_SHAPED_SOURCES: [&str; 1] = [r"'\s*(?:[\);]+\s*)?--|'[\);]*#(?:\n|\Z)"];

    let noise_prone: Vec<&str> = table::NOISE_PRONE_PATTERN_SOURCES.iter().copied().collect();
    assert_eq!(noise_prone.len(), 10, "registry must stay frozen");

    for source in TRIGRAM_SHAPED_SOURCES {
        assert!(
            noise_prone.contains(&source),
            "trigram-shaped source must stay in the noise-prone registry: {source}"
        );
    }

    let mut matched_sources: std::collections::HashSet<String> = std::collections::HashSet::new();
    for seed in NOISE_SEEDS {
        for content in [
            decode_latin1(&noise_bytes(seed)),
            decode_lossy(&noise_bytes(seed)),
        ] {
            // mirror detect: every view the scan passes run on
            let (processed, decoded, _) =
                preprocessor::preprocess_with_decoded(&content, 262_144, true, 10_000);
            let raw = preprocessor::preprocess_signal_preserving(&content, 262_144, true, 10_000);
            let url_decoded = preprocessor::truncate_safely(&decoded, 262_144, true, 10_000);
            let additive =
                preprocessor::short_base64_additive_view(&content, 262_144, true, 10_000);
            for view in [&processed, &raw, &url_decoded, &additive] {
                // zeroed prefix: prefix[high] - prefix[low] == 0 < 4, gate off
                let gate_off = vec![0u32; view.chars().count() + 1];
                for entry in patterns::COMPILED_TABLE.iter() {
                    if !table::NOISE_PRONE_PATTERN_SOURCES.contains(entry.entry.source) {
                        continue;
                    }
                    if patterns::find_first_threat(entry, view, "request_body", Some(&gate_off))
                        .is_some()
                    {
                        matched_sources.insert(entry.entry.source.to_owned());
                    }
                }
            }
        }
    }
    for source in &noise_prone {
        if TRIGRAM_SHAPED_SOURCES.contains(source) {
            continue;
        }
        assert!(
            matched_sources.contains(*source),
            "noise-prone pattern never fired on binary noise: {source}"
        );
    }
}

/// The PDF-prefix regression (upstream commit f5d53ca5): a PDF header whose
/// binary comment region contains an apostrophe, a newline and dashes must
/// not be reported as SQLi (real-world 558KB-PDF false positive).
#[test]
fn pdf_comment_line_with_sqli_terminator_bytes_not_flagged() {
    let pdf_prefix: &[u8] =
        b"%PDF-1.4\n%\xc7\x8f\xa2\n7 0 obj\n<</Length 8 0 R/Filter /FlateDecode>>\nstream\n";
    let mut buffer = pdf_prefix.to_vec();
    buffer.extend_from_slice(&noise_bytes(11)[..2000]);
    buffer[100..104].copy_from_slice(b"'\n--");

    let verdict = detect_str(&decode_lossy(&buffer));
    assert!(
        !verdict.is_threat,
        "PDF comment line with SQLi terminator bytes flagged: {:?}",
        verdict.threats
    );
    assert!(verdict.threats.is_empty());
}

/// The noise gate must not swallow genuine ASCII SQLi comment terminators.
#[test]
fn ascii_sqli_comment_terminator_outside_binary_still_detected() {
    let verdict = detect_str("users?name=1=1' \n-- drop table users");
    assert!(
        verdict.is_threat,
        "ASCII SQLi comment terminator not detected"
    );
    assert!(
        verdict.threats.iter().any(|t| matches!(
            t,
            Threat::Regex(r) if r.category == "sqli"
        )),
        "expected an sqli-category threat: {:?}",
        verdict.threats
    );
}

/// The SQLi comment-terminator source is registered as noise-prone: a match
/// whose neighborhood is binary-dense must be dropped by the gate equivalent
/// of the reference `_build_regex_threat` (`find_first_threat`), while the
/// same match in ASCII surroundings survives (covered by
/// `ascii_sqli_comment_terminator_outside_binary_still_detected`).
#[test]
fn sqli_comment_terminator_source_is_noise_gated() {
    const SOURCE: &str = r"'\s*(?:[\);]+\s*)?--|'[\);]*#(?:\n|\Z)";

    let dense_noise = decode_lossy(&noise_bytes(11));
    let dense_noise: String = dense_noise.chars().take(200).collect();
    let text = format!("abc \n' \n--{dense_noise}");

    let entry = patterns::COMPILED_TABLE
        .iter()
        .find(|e| e.entry.source == SOURCE)
        .expect("comment-terminator entry must exist in the compiled table");

    // Real density prefix over the fixture: the neighborhood right of the
    // match is binary dense, so the gated query must find nothing...
    let prefix = patterns::binary::build_binary_prefix(&text);
    assert!(
        patterns::find_first_threat(entry, &text, "request_body", Some(&prefix)).is_none(),
        "binary-dense comment-terminator match must be gated"
    );

    // ...and the gate must actually be load-bearing for this fixture: with a
    // zeroed prefix (gate off) the same match is accepted.
    let gate_off = vec![0u32; text.chars().count() + 1];
    assert!(
        patterns::find_first_threat(entry, &text, "request_body", Some(&gate_off)).is_some(),
        "comment-terminator match must survive with the gate off"
    );

    // The same match in ASCII surroundings is not gated either.
    assert!(
        patterns::find_first_threat(
            entry,
            "abc \n' \n-- drop table users",
            "request_body",
            Some(&prefix_for("abc \n' \n-- drop table users")),
        )
        .is_some(),
        "ASCII comment-terminator match must survive the gate"
    );
}

fn prefix_for(text: &str) -> Vec<u32> {
    patterns::binary::build_binary_prefix(text)
}
