//! One-off cost-curve benchmark on the shared parity workloads.
//! Run: `cargo run --release -p guard-core-benchmark --example cost_bench`

use guard_core_engine::detect::DetectConfig;
use guard_core_engine::detect::detect;
use std::time::Instant;

const fn config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
    }
}

fn main() {
    let cfg = config();
    let prose_unit = "The quick brown fox jumps over the lazy dog. \
Books, commas, and (parentheses); numbers like 2+2=4, dates like 2026-10-05, \
and the words do, as, or, the appear here for no reason at all. ";
    let threat_unit = "1' OR '1'='1 -- ";
    let to_size = |unit: &str, size: usize| unit.repeat(size / unit.len() + 1)[..size].to_string();

    let workloads: Vec<(&str, String, bool)> = vec![
        ("prose 8KiB", to_size(prose_unit, 8 * 1024), false),
        ("prose 64KiB", to_size(prose_unit, 64 * 1024), false),
        ("prose 256KiB", to_size(prose_unit, 256 * 1024), false),
        ("threat 8KiB", to_size(threat_unit, 8 * 1024), true),
    ];

    for (label, body, expect) in workloads {
        // warmup
        let warm = detect(&body, "request_body", &cfg);
        let warm_threat = warm.is_threat;
        let mut samples = Vec::new();
        let mut last_threat = warm_threat;
        for _ in 0..3 {
            let t0 = Instant::now();
            let v = detect(&body, "request_body", &cfg);
            last_threat = v.is_threat;
            samples.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "{label}: median {:.1} ms (min {:.1}, max {:.1}) threat={warm_threat}/{last_threat} expected={expect}",
            samples[1], samples[0], samples[2]
        );
    }
}
