use serde_json::Value;

#[derive(Debug)]
pub struct UnmappedKnob {
    pub name: String,
    pub recorded: Value,
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct Knobs {
    pub max_content_length: usize,
    pub max_truncate_bytes: usize,
    pub preserve_attack_patterns: bool,
    pub semantic_threshold: f64,
    pub threat_score_threshold: f64,
    pub unmapped: Vec<UnmappedKnob>,
}

const UNMAPPED_REASONS: &[(&str, &str)] = &[
    (
        "detection_compiler_timeout",
        "regex crate is finite-automata based; the engine has no per-scan timeout to configure",
    ),
    (
        "detection_max_tracked_patterns",
        "closest counterpart is PatternCache LRU capacity but the detect path compiles no tracked patterns yet",
    ),
    (
        "detection_anomaly_threshold",
        "PerformanceMonitor is not ported",
    ),
    (
        "detection_slow_pattern_threshold",
        "PerformanceMonitor is not ported",
    ),
    (
        "detection_monitor_history_size",
        "PerformanceMonitor is not ported",
    ),
    (
        "detection_anomaly_emission_cooldown",
        "PerformanceMonitor is not ported",
    ),
    (
        "detection_min_samples_for_anomaly",
        "PerformanceMonitor is not ported",
    ),
];

fn knob_usize(config_knobs: &Value, name: &str) -> Result<usize, String> {
    let raw = config_knobs
        .get(name)
        .ok_or_else(|| format!("config_knobs missing '{name}'"))?
        .as_f64()
        .ok_or_else(|| format!("config_knobs '{name}' is not a number"))?;
    if !raw.is_finite() || raw < 0.0 || raw.fract() != 0.0 {
        return Err(format!(
            "config_knobs '{name}' must be a non-negative integer, got {raw}"
        ));
    }
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "value validated above as a finite non-negative integer"
    )]
    let value = raw as usize;
    Ok(value)
}

pub fn map_knobs(config_knobs: &Value) -> Result<Knobs, String> {
    let obj = config_knobs
        .as_object()
        .ok_or("config_knobs must be an object")?;

    let get_number = |name: &str| -> Result<f64, String> {
        obj.get(name)
            .ok_or_else(|| format!("config_knobs missing '{name}'"))?
            .as_f64()
            .ok_or_else(|| format!("config_knobs '{name}' is not a number"))
    };

    let max_content_length = knob_usize(config_knobs, "detection_max_content_length")?;
    let max_truncate_bytes = knob_usize(config_knobs, "detection_max_body_inspect_bytes")?;
    let semantic_threshold = get_number("detection_semantic_threshold")?;
    let threat_score_threshold = get_number("detection_threat_score_threshold")?;

    let preserve_attack_patterns = match obj.get("detection_preserve_attack_patterns") {
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            return Err(format!(
                "config_knobs 'detection_preserve_attack_patterns' is not a bool: {other}"
            ));
        }
        None => return Err("config_knobs missing 'detection_preserve_attack_patterns'".into()),
    };

    let unmapped = UNMAPPED_REASONS
        .iter()
        .filter_map(|(name, reason)| {
            obj.get(*name).map(|recorded| UnmappedKnob {
                name: (*name).to_owned(),
                recorded: recorded.clone(),
                reason,
            })
        })
        .collect();

    Ok(Knobs {
        max_content_length,
        max_truncate_bytes,
        preserve_attack_patterns,
        semantic_threshold,
        threat_score_threshold,
        unmapped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn corpus_knobs() -> Value {
        json!({
            "detection_compiler_timeout": 2.0,
            "detection_max_tracked_patterns": 1000,
            "detection_max_content_length": 10000,
            "detection_preserve_attack_patterns": true,
            "detection_max_body_inspect_bytes": 262_144,
            "detection_anomaly_threshold": 3.0,
            "detection_slow_pattern_threshold": 0.1,
            "detection_monitor_history_size": 1000,
            "detection_anomaly_emission_cooldown": 60.0,
            "detection_min_samples_for_anomaly": 30,
            "detection_semantic_threshold": 0.7,
            "detection_threat_score_threshold": 1.0
        })
    }

    #[test]
    fn maps_corpus_knobs_and_lists_unmapped() {
        let knobs = map_knobs(&corpus_knobs()).expect("corpus knobs must map");
        assert_eq!(knobs.max_content_length, 10_000);
        assert_eq!(knobs.max_truncate_bytes, 262_144);
        assert!(knobs.preserve_attack_patterns);
        assert!((knobs.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((knobs.threat_score_threshold - 1.0).abs() < f64::EPSILON);

        let names: Vec<&str> = knobs.unmapped.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names.len(), 7);
        assert!(names.contains(&"detection_compiler_timeout"));
        assert!(names.contains(&"detection_max_tracked_patterns"));
        assert!(names.contains(&"detection_anomaly_threshold"));
        assert!(names.contains(&"detection_min_samples_for_anomaly"));
    }

    #[test]
    fn missing_or_mistyped_knob_is_an_error() {
        let mut broken = corpus_knobs();
        broken
            .as_object_mut()
            .unwrap()
            .remove("detection_semantic_threshold");
        assert!(map_knobs(&broken).is_err());

        let mut mistyped = corpus_knobs();
        mistyped.as_object_mut().unwrap().insert(
            "detection_preserve_attack_patterns".to_owned(),
            json!("yes"),
        );
        assert!(map_knobs(&mistyped).is_err());
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn non_integer_or_negative_or_nonfinite_knobs_are_rejected() {
        let config = |v: serde_json::Value| json!({ "detection_max_content_length": v });
        assert!(
            map_knobs(&config(json!("text"))).is_err(),
            "a string knob is rejected"
        );
        assert!(
            map_knobs(&config(json!(-3.5))).is_err(),
            "a negative fraction is rejected"
        );
        assert!(
            map_knobs(&config(json!(2.5))).is_err(),
            "a fraction is rejected"
        );
    }

    #[test]
    fn the_knob_container_must_be_an_object() {
        assert_eq!(
            map_knobs(&json!(["not", "an", "object"])).expect_err("array knobs"),
            "config_knobs must be an object"
        );
        assert_eq!(
            map_knobs(&json!("text")).expect_err("string knobs"),
            "config_knobs must be an object"
        );
    }

    #[test]
    fn missing_knobs_name_the_first_missing_key() {
        assert_eq!(
            map_knobs(&json!({})).expect_err("empty knobs"),
            "config_knobs missing 'detection_max_content_length'"
        );
        assert_eq!(
            map_knobs(&json!({ "detection_max_content_length": 1 }))
                .expect_err("missing inspect bytes"),
            "config_knobs missing 'detection_max_body_inspect_bytes'"
        );
        assert_eq!(
            map_knobs(&json!({
                "detection_max_content_length": 1,
                "detection_max_body_inspect_bytes": 2,
                "detection_semantic_threshold": 0.5,
            }))
            .expect_err("missing threat threshold"),
            "config_knobs missing 'detection_threat_score_threshold'"
        );
    }

    #[test]
    fn a_non_bool_attack_pattern_knob_is_rejected() {
        let config = |v: serde_json::Value| json!({ "detection_preserve_attack_patterns": v });
        assert!(
            map_knobs(&config(json!("yes"))).is_err(),
            "a string bool is rejected"
        );
        assert!(
            map_knobs(&config(json!(1))).is_err(),
            "a numeric bool is rejected"
        );
    }
}

#[cfg(test)]
mod number_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn non_numeric_knob_values_are_rejected() {
        let mut config = json!({
            "detection_max_content_length": 10000,
            "detection_max_body_inspect_bytes": 262_144,
            "detection_semantic_threshold": 0.7,
            "detection_threat_score_threshold": 1.0,
            "detection_preserve_attack_patterns": true,
        });
        config["detection_semantic_threshold"] = json!("high");
        assert_eq!(
            map_knobs(&config).err().unwrap(),
            "config_knobs 'detection_semantic_threshold' is not a number"
        );
    }

    #[test]
    fn missing_preserve_attack_patterns_knob_is_rejected() {
        let config = json!({
            "detection_max_content_length": 10000,
            "detection_max_body_inspect_bytes": 262_144,
            "detection_semantic_threshold": 0.7,
            "detection_threat_score_threshold": 1.0,
        });
        assert_eq!(
            map_knobs(&config).err().unwrap(),
            "config_knobs missing 'detection_preserve_attack_patterns'"
        );
    }
}
