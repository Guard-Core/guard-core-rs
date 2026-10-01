//! Ambiguous optional tail detection and atom character semantics.
//!
//! Port of the reference `_redos_ambiguous_tail.py`. The atom character
//! sets are computed from the parsed op tree (the reference compiles the
//! atom with `re.DOTALL` and fullmatches `string.printable`; a parsed
//! single node has identical per-character semantics).

use super::ast::{self, Flags};
use super::parse_slots::{PRINTABLE, candidate_chars_for_atom_text, node_intervals};
use super::structure::{
    NestingTooDeep, iter_quantified_group_bodies, nesting_depth_rejection_reason, skip_char_class,
};

fn dotall_flags() -> Flags {
    Flags {
        dotall: true,
        ..Flags::default()
    }
}

fn parsed_single_intervals(atom_text: &str) -> Option<super::intervals::IntervalSet> {
    let (ops, final_flags) = ast::parse(atom_text, dotall_flags()).ok()?;
    if ops.len() != 1 {
        return None;
    }
    Some(node_intervals(&ops[0], final_flags))
}

/// The printable characters the atom matches (reference `_atom_char_set`).
#[must_use]
pub fn atom_char_set(atom_text: &str) -> Vec<char> {
    let Some(intervals) = parsed_single_intervals(atom_text) else {
        return Vec::new();
    };
    PRINTABLE
        .iter()
        .copied()
        .filter(|c| intervals.contains(u32::from(*c)))
        .collect()
}

/// Whether two atom texts overlap on any printable character.
#[must_use]
pub fn atoms_overlap(text_a: &str, text_b: &str) -> bool {
    let set_a = atom_char_set(text_a);
    let set_b = atom_char_set(text_b);
    set_a.iter().any(|c| set_b.contains(c))
}

/// The first printable character the atom matches, else the first
/// interval-endpoint candidate (reference `_representative_char_for_atom`).
#[must_use]
pub fn representative_char_for_atom(atom_text: &str) -> Option<char> {
    let intervals = parsed_single_intervals(atom_text)?;
    for c in PRINTABLE {
        if intervals.contains(u32::from(*c)) {
            return Some(*c);
        }
    }
    candidate_chars_for_atom_text(atom_text, dotall_flags())
        .into_iter()
        .next()
}

fn parse_symbol_quantifier(inner: &[char], i: usize) -> (bool, bool, usize) {
    let symbol = inner[i];
    let optional = symbol == '*' || symbol == '?';
    let unbounded = symbol == '*' || symbol == '+';
    let mut i = i + 1;
    if i < inner.len() && inner[i] == '?' {
        i += 1;
    }
    (optional, unbounded, i)
}

fn raw_atom_span(inner: &[char], i: usize) -> usize {
    if inner[i] == '\\' && i + 1 < inner.len() {
        return i + 2;
    }
    if inner[i] == '[' {
        return skip_char_class(inner, i);
    }
    i + 1
}

fn atoms_have_ambiguous_pair(atoms: &[(bool, bool)]) -> bool {
    for a in 0..atoms.len() {
        for b in 0..atoms.len() {
            if atoms[a].1 && atoms[b].0 && a != b {
                return true;
            }
        }
    }
    false
}

fn parse_brace_quantifier_with_variability(
    inner: &[char],
    i: usize,
) -> Option<(bool, bool, bool, usize)> {
    let end_brace = inner[i..].iter().position(|c| *c == '}')? + i;
    let parts: Vec<String> = inner[i + 1..end_brace]
        .iter()
        .collect::<String>()
        .split(',')
        .map(str::to_owned)
        .collect();
    if !parts[0].chars().all(|c| c.is_ascii_digit()) || parts[0].is_empty() {
        return None;
    }
    let optional = parts[0] == "0";
    let unbounded = parts.len() > 1 && parts[1].is_empty();
    let variable = unbounded || (parts.len() > 1 && parts[1] != parts[0]);
    let mut j = end_brace + 1;
    if j < inner.len() && inner[j] == '?' {
        j += 1;
    }
    Some((optional, unbounded, variable, j))
}

/// Flat atom scan keeping atom text and variability flags (reference
/// `_parse_flat_quantified_atoms_with_text`).
#[must_use]
pub fn parse_flat_quantified_atoms_with_text(
    inner: &str,
) -> Option<Vec<(String, bool, bool, bool)>> {
    let chars: Vec<char> = inner.chars().collect();
    let mut atoms: Vec<(String, bool, bool, bool)> = Vec::new();
    let mut i = 0usize;
    let n = chars.len();
    while i < n {
        if chars[i] == '(' || chars[i] == '|' {
            return None;
        }
        let atom_end = raw_atom_span(&chars, i);
        let atom_text: String = chars[i..atom_end].iter().collect();
        i = atom_end;
        let (mut optional, mut unbounded, mut variable) = (false, false, false);
        if i < n && matches!(chars[i], '*' | '+' | '?') {
            (optional, unbounded, i) = parse_symbol_quantifier(&chars, i);
            variable = true;
        } else if i < n && chars[i] == '{' {
            let parsed = parse_brace_quantifier_with_variability(&chars, i)?;
            (optional, unbounded, variable, i) = parsed;
        }
        atoms.push((atom_text, optional, unbounded, variable));
    }
    Some(atoms)
}

fn has_overlapping_cyclic_neighbor(atoms: &[(String, bool, bool, bool)]) -> bool {
    let n = atoms.len();
    for (k, (_text_k, _optional_k, _unbounded_k, variable_k)) in atoms.iter().enumerate() {
        if !variable_k {
            continue;
        }
        let next_text = &atoms[(k + 1) % n].0;
        if atoms_overlap(_text_k, next_text) {
            return true;
        }
    }
    false
}

/// Reference `_group_inner_is_ambiguous`.
#[must_use]
pub fn group_inner_is_ambiguous(inner: &str) -> bool {
    let Some(raw_atoms) = parse_flat_quantified_atoms_with_text(inner) else {
        return false;
    };
    if raw_atoms.len() == 1 {
        let (_text, _optional, unbounded, variable) = &raw_atoms[0];
        return *variable && !unbounded;
    }
    let shape_only: Vec<(bool, bool)> = raw_atoms.iter().map(|(_, o, u, _)| (*o, *u)).collect();
    if atoms_have_ambiguous_pair(&shape_only) {
        return true;
    }
    has_overlapping_cyclic_neighbor(&raw_atoms)
}

/// Reference `_detect_ambiguous_optional_tail_in_quantified_group`.
#[must_use]
pub fn detect_ambiguous_optional_tail_in_quantified_group(pattern: &str) -> Option<String> {
    match iter_quantified_group_bodies(pattern) {
        Ok(bodies) => bodies
            .into_iter()
            .find(|(_, _, inner)| group_inner_is_ambiguous(inner))
            .map(|(start, end, _)| {
                let chars: Vec<char> = pattern.chars().collect();
                chars[start..end.min(chars.len())].iter().collect()
            }),
        Err(NestingTooDeep) => Some(nesting_depth_rejection_reason()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_char_sets_come_from_the_parsed_intervals() {
        assert_eq!(atom_char_set(r"[a-c]"), vec!['a', 'b', 'c']);
        assert_eq!(atom_char_set("a"), vec!['a']);
        assert!(atom_char_set(r"\d").iter().all(|c| c.is_ascii_digit()));
        assert_eq!(atom_char_set(r"\1"), Vec::<char>::new());
        assert_eq!(atom_char_set("[oops"), Vec::<char>::new());
        // Dotall semantics: `.` matches every printable character.
        assert_eq!(atom_char_set(".").len(), PRINTABLE.len());
    }

    #[test]
    fn atoms_overlap_on_any_shared_printable() {
        assert!(atoms_overlap("[a-c]", "[b-d]"));
        assert!(!atoms_overlap("[a-c]", "[x-z]"));
        assert!(!atoms_overlap(r"\1", "a"));
    }

    #[test]
    fn representative_char_prefers_the_printable_scan() {
        assert_eq!(representative_char_for_atom(r"[a-c]"), Some('a'));
        assert_eq!(representative_char_for_atom(r"\d"), Some('0'));
        assert_eq!(representative_char_for_atom("a"), Some('a'));
        // Past the printable alphabet the interval endpoints step in.
        assert_eq!(representative_char_for_atom(r"\x00"), Some('\0'));
        assert_eq!(representative_char_for_atom(r"\1"), None);
        assert_eq!(representative_char_for_atom("[oops"), None);
        assert_eq!(representative_char_for_atom(r"\p"), None);
    }

    #[test]
    fn symbol_quantifier_parsing_covers_lazy_markers() {
        let chars: Vec<char> = "a*?b".chars().collect();
        assert_eq!(parse_symbol_quantifier(&chars, 1), (true, true, 3));
        let chars: Vec<char> = "a+b".chars().collect();
        assert_eq!(parse_symbol_quantifier(&chars, 1), (false, true, 2));
        let chars: Vec<char> = "a?b".chars().collect();
        assert_eq!(parse_symbol_quantifier(&chars, 1), (true, false, 2));
    }

    #[test]
    fn brace_quantifier_with_variability() {
        let chars: Vec<char> = "a{2,5}b".chars().collect();
        assert_eq!(
            parse_brace_quantifier_with_variability(&chars, 1),
            Some((false, false, true, 6))
        );
        let chars: Vec<char> = "a{0,}b".chars().collect();
        assert_eq!(
            parse_brace_quantifier_with_variability(&chars, 1),
            Some((true, true, true, 5))
        );
        let chars: Vec<char> = "a{2}b".chars().collect();
        assert_eq!(
            parse_brace_quantifier_with_variability(&chars, 1),
            Some((false, false, false, 4))
        );
        let chars: Vec<char> = "a{x}b".chars().collect();
        assert_eq!(parse_brace_quantifier_with_variability(&chars, 1), None);
        let chars: Vec<char> = "a{2".chars().collect();
        assert_eq!(parse_brace_quantifier_with_variability(&chars, 1), None);
    }

    #[test]
    fn flat_atom_scan_propagates_a_malformed_brace_quantifier() {
        // `{x` is neither a valid quantifier nor plain literal text here,
        // so the whole scan answers None like the reference parser.
        assert_eq!(parse_flat_quantified_atoms_with_text("a{x}b"), None);
        assert_eq!(parse_flat_quantified_atoms_with_text("a{2"), None);
    }

    #[test]
    fn flat_atom_scan_rejects_groups_and_alternations() {
        assert!(parse_flat_quantified_atoms_with_text("a|b").is_none());
        assert!(parse_flat_quantified_atoms_with_text("(a)").is_none());
        assert!(parse_flat_quantified_atoms_with_text("ab?").is_some());
    }

    #[test]
    fn group_inner_ambiguity_rules() {
        // A single variable non-unbounded atom is ambiguous.
        assert!(group_inner_is_ambiguous("a?"));
        assert!(!group_inner_is_ambiguous("a*"));
        assert!(!group_inner_is_ambiguous("a"));
        // Unbounded atom followed by an optional atom is an ambiguous pair.
        assert!(group_inner_is_ambiguous(r"\w+\s?"));
        assert!(!group_inner_is_ambiguous(r"\w+\s"));
        // Cyclic overlap between variable neighbors.
        assert!(group_inner_is_ambiguous("[a-c]*[b-d]*"));
    }

    #[test]
    fn detector_reports_the_quantified_group_span() {
        assert_eq!(
            detect_ambiguous_optional_tail_in_quantified_group(r"(a?)+$"),
            Some("(a?)+".to_owned())
        );
        assert_eq!(
            detect_ambiguous_optional_tail_in_quantified_group("(abc)+"),
            None
        );
        let deep = format!("{}a?{}", "(".repeat(25), ")".repeat(25));
        assert_eq!(
            detect_ambiguous_optional_tail_in_quantified_group(&deep),
            Some(nesting_depth_rejection_reason())
        );
    }

    #[test]
    fn nested_ambiguous_group_is_found_by_the_outer_scan() {
        assert_eq!(
            detect_ambiguous_optional_tail_in_quantified_group(r"((\d{1,3}))+$"),
            Some(r"((\d{1,3}))+".to_owned())
        );
    }

    #[test]
    fn multi_op_atom_texts_have_no_single_interval() {
        // A two-literal atom text parses to two ops, so it has no single
        // atom interval and no representative char.
        assert!(atom_char_set("ab").is_empty());
        assert_eq!(representative_char_for_atom("ab"), None);
    }

    #[test]
    fn lazy_bounded_braces_advance_past_the_marker() {
        // The lazy marker after a brace quantifier is consumed by the atom
        // walk.
        let atoms = parse_flat_quantified_atoms_with_text(r"a{2,3}?b").expect("atoms");
        assert_eq!(atoms.len(), 2);
    }
}
