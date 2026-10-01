//! Ambiguous optional tail detection and atom character semantics.
//!
//! Port of the reference `_redos_ambiguous_tail.py`. The atom character
//! sets are computed from the parsed op tree (the reference compiles the
//! atom with `re.DOTALL` and fullmatches `string.printable`; a parsed
//! single node has identical per-character semantics).

use super::ast::{self, Flags};
use super::parse_slots::{candidate_chars_for_atom_text, node_intervals, PRINTABLE};
use super::structure::{
    iter_quantified_group_bodies, nesting_depth_rejection_reason, skip_char_class,
    NestingTooDeep,
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
    let shape_only: Vec<(bool, bool)> =
        raw_atoms.iter().map(|(_, o, u, _)| (*o, *u)).collect();
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
