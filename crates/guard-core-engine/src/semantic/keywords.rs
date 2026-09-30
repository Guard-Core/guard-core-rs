use std::collections::HashMap;
use std::collections::HashSet;

/// Keyword sets per attack category (xss, sql, command, path, template).
///
/// Used by [`super::analyze_attack_probability`] for base score calculation.
/// Construct with `Default::default()` for the built-in keyword tables.
pub struct AttackKeywords {
    categories: HashMap<&'static str, HashSet<&'static str>>,
}

impl AttackKeywords {
    /// All categories as `name -> keyword set` map.
    #[must_use]
    pub const fn all(&self) -> &HashMap<&'static str, HashSet<&'static str>> {
        &self.categories
    }
}

impl Default for AttackKeywords {
    fn default() -> Self {
        let categories = HashMap::from([
            (
                "xss",
                HashSet::from([
                    "script",
                    "javascript",
                    "onerror",
                    "onload",
                    "onclick",
                    "onmouseover",
                    "alert",
                    "eval",
                    "document",
                    "cookie",
                    "window",
                    "location",
                ]),
            ),
            (
                "sql",
                HashSet::from([
                    "select",
                    "union",
                    "insert",
                    "update",
                    "delete",
                    "drop",
                    "from",
                    "where",
                    "order",
                    "group",
                    "having",
                    "concat",
                    "substring",
                    "database",
                    "table",
                    "column",
                ]),
            ),
            (
                "command",
                HashSet::from([
                    "exec",
                    "system",
                    "shell",
                    "cmd",
                    "bash",
                    "powershell",
                    "wget",
                    "curl",
                    "nc",
                    "netcat",
                    "chmod",
                    "chown",
                    "sudo",
                    "passwd",
                ]),
            ),
            (
                "path",
                HashSet::from([
                    "etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini",
                ]),
            ),
            (
                "template",
                HashSet::from([
                    "render",
                    "template",
                    "jinja",
                    "mustache",
                    "handlebars",
                    "ejs",
                    "pug",
                    "twig",
                ]),
            ),
        ]);
        Self { categories }
    }
}

#[cfg(test)]
mod empty_category_tests {
    use super::*;

    #[test]
    fn an_empty_category_scores_zero_without_blocking_the_rest() {
        // a caller can wire a category with no keywords yet: it scores 0.0
        // while the populated categories still compute normally
        let keywords = AttackKeywords {
            categories: HashMap::from([
                ("empty_kind", HashSet::new()),
                ("path", HashSet::from(["etc", "passwd"])),
            ]),
        };
        let probabilities = crate::semantic::attack_probability_with_tokens(
            "/etc/passwd",
            &[String::from("etc"), String::from("passwd")],
            &keywords,
        );
        assert!(probabilities["empty_kind"].abs() < f64::EPSILON);
        assert!(probabilities["path"] > 0.0, "path: {probabilities:?}");
    }
}
