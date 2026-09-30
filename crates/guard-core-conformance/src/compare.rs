use serde_json::Value;
use std::collections::BTreeMap;

pub const EXCLUDED_FIELD: &str = "execution_time";

#[must_use]
pub fn round6(f: f64) -> f64 {
    (f * 1_000_000.0).round() / 1_000_000.0
}

pub fn canonicalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove(EXCLUDED_FIELD);
            for (_, v) in map.iter_mut() {
                canonicalize(v);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                canonicalize(item);
            }
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64()
                && let Some(rounded) = serde_json::Number::from_f64(round6(f))
            {
                *n = rounded;
            }
        }
        _ => {}
    }
}

#[must_use]
pub fn threat_multiset(threats: &[Value]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for threat in threats {
        // The multiset key must be key-order insensitive: a parsed
        // expectation and a constructed verdict can carry the same object
        // under different key orders (serde_json's preserve_order keeps
        // insertion order, so the string form follows the producer).
        let mut normalized = threat.clone();
        sort_object_keys(&mut normalized);
        *counts.entry(normalized.to_string()).or_insert(0) += 1;
    }
    counts
}

/// Recursively sort every object's keys, so a serialized form is stable
/// across producers that insert in different orders.
pub fn sort_object_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| {
                    let mut v = v.clone();
                    sort_object_keys(&mut v);
                    (k.clone(), v)
                })
                .collect::<Vec<(String, Value)>>()
                .into_iter()
                .collect::<BTreeMap<String, Value>>()
                .into_iter()
                .collect();
            *map = sorted;
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                sort_object_keys(item);
            }
        }
        _ => {}
    }
}

pub fn compare_verdicts(got: &Value, want: &Value) -> Vec<String> {
    let mut diffs = Vec::new();

    if got.get("is_threat") != want.get("is_threat") {
        diffs.push(format!(
            "is_threat: got {} want {}",
            display_field(got.get("is_threat")),
            display_field(want.get("is_threat"))
        ));
    }

    let got_score = got.get("threat_score").and_then(Value::as_f64).map(round6);
    let want_score = want.get("threat_score").and_then(Value::as_f64).map(round6);
    if got_score != want_score {
        diffs.push(format!(
            "threat_score: got {got_score:?} want {want_score:?} (6-decimal compare)"
        ));
    }

    for field in ["original_length", "processed_length"] {
        if got.get(field) != want.get(field) {
            diffs.push(format!(
                "{field}: got {} want {}",
                display_field(got.get(field)),
                display_field(want.get(field))
            ));
        }
    }

    if got.get("detection_method") != want.get("detection_method") {
        diffs.push(format!(
            "detection_method: got {} want {}",
            display_field(got.get("detection_method")),
            display_field(want.get("detection_method"))
        ));
    }

    let empty = Vec::new();
    let got_threats = got
        .get("threats")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let want_threats = want
        .get("threats")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    if threat_multiset(got_threats) != threat_multiset(want_threats) {
        diffs.push(format!(
            "threats: got {} want {}",
            summarize_threats(got_threats),
            summarize_threats(want_threats)
        ));
    }

    diffs
}

fn display_field(v: Option<&Value>) -> String {
    v.map_or_else(|| "missing".to_owned(), ToString::to_string)
}

#[must_use]
pub fn summarize_threats(threats: &[Value]) -> String {
    let parts: Vec<String> = threats
        .iter()
        .map(|t| {
            format!(
                "{}|{}@{}",
                display_field(t.get("category")),
                short(display_field(t.get("pattern")).as_str()),
                display_field(t.get("position"))
            )
        })
        .collect();
    format!("[{}]", parts.join("; "))
}

fn short(p: &str) -> String {
    if p.len() > 40 {
        p[..40].to_owned()
    } else {
        p.to_owned()
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    reason = "round6 output is pinned to exact 6-decimal values by design"
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round6_matches_reference_precision() {
        assert_eq!(round6(0.123_456_49), 0.123_456);
        assert_eq!(round6(0.123_456_5), 0.123_457);
        assert_eq!(round6(1.0), 1.0);
        assert_eq!(round6(0.0), 0.0);
    }

    #[test]
    fn canonicalize_drops_execution_time_recursively() {
        let mut v = json!({
            "a": 1.123_456_789,
            "execution_time": 0.5,
            "nested": [{ "execution_time": 0.25, "x": 2.0 }],
        });
        canonicalize(&mut v);
        assert!(v.get("execution_time").is_none());
        assert!(v["nested"][0].get("execution_time").is_none());
        assert_eq!(v["a"], json!(1.123_457));
    }

    #[test]
    fn threat_multiset_is_order_insensitive_and_count_aware() {
        let a = vec![
            json!({"p": "x", "position": 1}),
            json!({"p": "y", "position": 2}),
        ];
        let b = vec![
            json!({"p": "y", "position": 2}),
            json!({"p": "x", "position": 1}),
        ];
        assert_eq!(threat_multiset(&a), threat_multiset(&b));

        let c = vec![json!({"p": "x", "position": 1}); 2];
        let d = vec![json!({"p": "x", "position": 1})];
        assert_ne!(threat_multiset(&c), threat_multiset(&d));
    }

    #[test]
    fn compare_reports_every_normative_field() {
        let got = json!({
            "is_threat": false,
            "threat_score": 1.0,
            "original_length": 5,
            "processed_length": 6,
            "detection_method": "enhanced",
            "threats": [],
        });
        let want = json!({
            "is_threat": true,
            "threat_score": 0.5,
            "original_length": 5,
            "processed_length": 7,
            "detection_method": "legacy",
            "threats": [json!({"pattern": "p", "position": 0})],
        });
        let diffs = compare_verdicts(&got, &want);
        assert_eq!(diffs.len(), 5);
        assert!(diffs[0].starts_with("is_threat"));
        assert!(diffs[1].starts_with("threat_score"));
        assert!(diffs[2].starts_with("processed_length"));
        assert!(diffs[3].starts_with("detection_method"));
        assert!(diffs[4].starts_with("threats"));

        let mut got_canon = json!({
            "is_threat": true,
            "threat_score": 0.999_999_949,
            "original_length": 5,
            "processed_length": 7,
            "detection_method": "enhanced",
            "threats": [json!({"pattern": "p", "position": 0})],
        });
        let mut want_canon = json!({
            "is_threat": true,
            "threat_score": 0.999_999_9,
            "original_length": 5,
            "processed_length": 7,
            "detection_method": "enhanced",
            "threats": [json!({"pattern": "p", "position": 0, "execution_time": 0.1})],
        });
        canonicalize(&mut got_canon);
        canonicalize(&mut want_canon);
        assert!(compare_verdicts(&got_canon, &want_canon).is_empty());
    }
}

#[cfg(test)]
mod summarize_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summarize_threats_truncates_long_patterns() {
        let long_pattern = "a".repeat(60);
        let threats = vec![json!({
            "category": "sqli",
            "pattern": long_pattern,
            "position": 7,
        })];
        let summary = summarize_threats(&threats);
        // the JSON-quoted pattern is truncated to 40 characters: the opening
        // quote plus 39 letters
        assert!(summary.starts_with("[\"sqli\"|"), "unexpected: {summary}");
        assert!(summary.contains(&format!("\"{}", "a".repeat(39))));
        assert!(!summary.contains(&"a".repeat(40)));
        assert!(summary.ends_with("@7]"), "unexpected: {summary}");
    }
}
