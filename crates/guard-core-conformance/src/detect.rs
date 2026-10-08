use guard_core_engine::detect::{self, DetectConfig, Threat};
use serde_json::{Map, Value, json};

use crate::knobs::Knobs;

pub const DETECTION_METHOD: &str = "enhanced";

#[derive(Debug)]
pub struct Verdict {
    pub is_threat: bool,
    pub threat_score: f64,
    pub threats: Vec<Value>,
    pub original_length: usize,
    pub processed_length: usize,
}

/// The ENGINE's detect (spec 4.1.0 `SusPatternsManager.detect` pipeline);
/// this adapter only maps the typed verdict to the corpus JSON shape.
#[must_use]
pub fn detect(content: &str, request_context: &str, knobs: &Knobs) -> Verdict {
    let config = DetectConfig {
        max_content_length: knobs.max_content_length,
        max_full_scan_bytes: knobs.max_truncate_bytes,
        preserve_attack_patterns: knobs.preserve_attack_patterns,
        semantic_threshold: knobs.semantic_threshold,
        threat_score_threshold: knobs.threat_score_threshold,
        // The corpus is pinned at spec 4.1.0, before
        // `detection_binary_min_run_length` existed; the reference default
        // applies and body extraction is not part of the recorded surface.
        binary_min_run_length: 16,
        max_scan_values: 512,
        max_scan_chars: 65_536,
        max_json_depth: 32,
    };
    let verdict = detect::detect(content, request_context, &config);

    Verdict {
        is_threat: verdict.is_threat,
        threat_score: verdict.threat_score,
        threats: verdict.threats.iter().map(threat_json).collect(),
        original_length: verdict.original_length,
        processed_length: verdict.processed_length,
    }
}

fn threat_json(threat: &Threat) -> Value {
    match threat {
        Threat::Regex(r) => json!({
            "type": "regex",
            "pattern": r.pattern,
            "match": r.match_text,
            "position": r.position,
            "category": r.category,
            "weight": r.weight,
        }),
        Threat::Semantic(s) => {
            if s.fallback {
                json!({
                    "type": "semantic",
                    "attack_type": s.attack_type,
                    "threat_score": s.score,
                    "analysis": analysis_json(&s.analysis),
                })
            } else {
                json!({
                    "type": "semantic",
                    "attack_type": s.attack_type,
                    "probability": s.score,
                    "analysis": analysis_json(&s.analysis),
                })
            }
        }
    }
}

fn analysis_json(analysis: &guard_core_engine::semantic::AnalysisResult) -> Value {
    let mut probabilities = Map::new();
    let mut keys: Vec<&&str> = analysis.attack_probabilities.keys().collect();
    keys.sort();
    for key in keys {
        probabilities.insert(
            (*key).to_owned(),
            json!(analysis.attack_probabilities[*key]),
        );
    }

    let suspicious: Vec<Value> = analysis
        .suspicious_patterns
        .iter()
        .map(|p| {
            json!({
                "type": p.pattern_type,
                "pattern": p.matched,
                "position": p.position,
                "context": p.context,
            })
        })
        .collect();

    json!({
        "attack_probabilities": probabilities,
        "entropy": analysis.entropy,
        "encoding_layers": analysis.encoding_layers,
        "is_obfuscated": analysis.is_obfuscated,
        "suspicious_patterns": suspicious,
        "code_injection_risk": analysis.code_injection_risk,
        "token_count": analysis.token_count,
    })
}

impl Verdict {
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "is_threat": self.is_threat,
            "threat_score": self.threat_score,
            "threats": self.threats,
            "original_length": self.original_length,
            "processed_length": self.processed_length,
            "detection_method": DETECTION_METHOD,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knobs::map_knobs;

    fn corpus_knobs() -> Knobs {
        map_knobs(&json!({
            "detection_max_content_length": 10000,
            "detection_max_body_inspect_bytes": 262_144,
            "detection_preserve_attack_patterns": true,
            "detection_semantic_threshold": 0.7,
            "detection_threat_score_threshold": 1.0
        }))
        .expect("corpus knobs must map")
    }

    // the runner compares positions natively against corpus expectations, so
    // verdicts must carry code-point indices (Python str index space), not
    // byte offsets. Payload is sem_structural_dense with a 10-code-point CJK
    // prefix (30 bytes) so a byte offset would read 45/73/86.
    #[test]
    fn suspicious_pattern_positions_are_codepoint_indices() {
        let knobs = corpus_knobs();

        let content = "测试测试测试测试测试${x} <t> (y) [z] {w} a://b c://d \
                       <b>call(f(x))</b> union select concat(database(),table_name) \
                       from information_schema.tables where 1=1 \
                       {{render(jinja(template(mustache(handlebars(ejs(pug(twig)))))))}}";
        let verdict = detect(content, "request_body", &knobs);
        assert!(
            !verdict.threats.is_empty(),
            "payload must emit semantic threats for the position check"
        );
        let positions: Vec<u64> = verdict
            .threats
            .iter()
            .filter(|t| t["type"] == "semantic")
            .flat_map(|t| t["analysis"]["suspicious_patterns"].as_array().unwrap())
            .filter(|p| p["type"] == "tag_like")
            .map(|p| p["position"].as_u64().unwrap())
            .collect();
        assert_eq!(positions, [15, 43, 56]);
    }

    #[test]
    fn regex_threat_positions_are_codepoint_indices() {
        let knobs = corpus_knobs();
        // pattern id 1 fires at code-point 6 (byte offset 18 with the CJK prefix)
        let content = "测试测试测试javascript:alert(1)";
        let verdict = detect(content, "request_body", &knobs);
        let script_threat = verdict
            .threats
            .iter()
            .find(|t| t["pattern"] == json!("javascript:\\s*[^\\s]+"))
            .expect("javascript: threat");
        assert_eq!(script_threat["position"].as_u64(), Some(6));
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;
    use crate::knobs::map_knobs;

    fn corpus_knobs() -> Knobs {
        map_knobs(&json!({
            "detection_max_content_length": 10000,
            "detection_max_body_inspect_bytes": 262_144,
            "detection_preserve_attack_patterns": true,
            "detection_semantic_threshold": 0.7,
            "detection_threat_score_threshold": 1.0
        }))
        .expect("corpus knobs must map")
    }

    #[test]
    fn a_fallback_semantic_threat_serializes_its_threat_score_shape() {
        // a payload whose aggregate score clears the threshold without any
        // single attack class: the fallback threat renders the `threat_score`
        // shape instead of a per-type probability
        let content = format!("from where drop select {} ({{}}$x==) foo(", "A".repeat(120));
        let verdict = detect(&content, "request_body", &corpus_knobs());
        let fallback = verdict
            .threats
            .iter()
            .find(|t| t["type"] == "semantic" && t["threat_score"].is_number())
            .expect("the fallback semantic shape renders");
        assert_eq!(fallback["attack_type"], json!("suspicious"));
        assert!(fallback["analysis"].is_object());
    }
}
