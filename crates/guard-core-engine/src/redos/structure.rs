//! String-level structural analysis primitives and the nested/adjacent
//! unbounded-quantifier rules.
//!
//! Port of the reference `_redos_structure_primitives.py` and
//! `_redos_structure_rules.py` (assembled by `_redos_structure.py`): all
//! analysis happens over the raw pattern source, exactly as in Python.

/// Maximum group nesting depth the structural analyzer supports.
pub const MAX_GROUP_NESTING_DEPTH: usize = 20;

/// Rejection reason returned when the depth cap trips.
#[must_use]
pub fn nesting_depth_rejection_reason() -> String {
    format!(
        "pattern exceeds the maximum group nesting depth of \
         {MAX_GROUP_NESTING_DEPTH} the ReDoS structural analyzer supports"
    )
}

/// The reference `GroupNestingTooDeep` signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestingTooDeep;

pub type StructureResult<T> = Result<T, NestingTooDeep>;

/// Skip a `[...]` class starting at `i`; returns the index past `]`.
#[must_use]
pub fn skip_char_class(text: &[char], i: usize) -> usize {
    let mut j = i + 1;
    while j < text.len() && text[j] != ']' {
        if text[j] == '\\' && j + 1 < text.len() {
            j += 2;
            continue;
        }
        j += 1;
    }
    if j < text.len() {
        j += 1;
    }
    j
}

/// Replace escapes and char classes with `X` placeholders.
#[must_use]
pub fn strip_escapes_and_char_classes(pattern: &[char]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < pattern.len() {
        let c = pattern[i];
        if c == '\\' && i + 1 < pattern.len() {
            result.push('X');
            i += 2;
            continue;
        }
        if c == '[' {
            i = skip_char_class(pattern, i);
            result.push('X');
            continue;
        }
        result.push(c);
        i += 1;
    }
    result
}

/// Whether a branch is `.` quantified unbounded exactly once: `.*`, `.+`
/// or `.{n,}`.
#[must_use]
pub fn branch_is_unbounded_single(branch: &str) -> bool {
    let chars: Vec<char> = branch.chars().collect();
    if chars.len() == 2 && (chars[1] == '*' || chars[1] == '+') {
        return true;
    }
    // `.` + `{` + digits + `,` + `}`
    if chars.len() >= 5 && chars[1] == '{' && chars[chars.len() - 1] == '}' {
        let inner = &chars[2..chars.len() - 1];
        let comma = inner.iter().position(|c| *c == ',');
        if let Some(comma) = comma {
            return comma >= 1
                && comma == inner.len() - 1
                && inner[..comma].iter().all(|c| c.is_ascii_digit());
        }
    }
    false
}

/// Advance past an escape pair or a whole char class.
#[must_use]
pub fn advance_past_escape_or_char_class(text: &[char], i: usize) -> Option<usize> {
    if text[i] == '\\' && i + 1 < text.len() {
        return Some(i + 2);
    }
    if text[i] == '[' {
        return Some(skip_char_class(text, i));
    }
    None
}

/// Index just past the group whose `(` is at `start`.
#[must_use]
pub fn find_group_end(text: &[char], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut j = start + 1;
    while j < text.len() && depth > 0 {
        if let Some(skip_to) = advance_past_escape_or_char_class(text, j) {
            j = skip_to;
            continue;
        }
        match text[j] {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    (depth == 0).then_some(j)
}

/// Strip `?:` / `?P<name>` group prefixes; `None` for unsupported heads.
#[must_use]
pub fn normalize_group_inner(inner: &[char]) -> Option<String> {
    if inner.starts_with(&['?', ':']) {
        return Some(inner[2..].iter().collect());
    }
    if inner.starts_with(&['?', 'P', '=']) {
        return None;
    }
    if inner.starts_with(&['?', 'P', '<']) {
        let end_name = inner.iter().position(|c| *c == '>')?;
        return Some(inner[end_name + 1..].iter().collect());
    }
    Some(inner.iter().collect())
}

/// Peel leading transparent wrappers that span the whole text.
#[must_use]
pub fn unwrap_transparent_wrapper(text: &str) -> String {
    let mut text = text.to_owned();
    loop {
        if !text.starts_with('(') {
            break;
        }
        let chars: Vec<char> = text.chars().collect();
        let Some(end) = find_group_end(&chars, 0) else {
            break;
        };
        if end != chars.len() {
            break;
        }
        let Some(candidate) = normalize_group_inner(&chars[1..end - 1]) else {
            break;
        };
        text = candidate;
    }
    text
}

/// Length of the unbounded quantifier at `k` (`*`, `+`, `{n,}`), else 0.
#[must_use]
pub fn outer_quantifier_len(text: &[char], k: usize) -> usize {
    if k < text.len() && (text[k] == '*' || text[k] == '+') {
        return 1;
    }
    if k < text.len() && text[k] == '{' {
        if let Some(offset) = text[k..].iter().position(|c| *c == '}') {
            let end_brace = k + offset;
            let brace_inner: String = text[k + 1..end_brace].iter().collect();
            if let Some(pos) = brace_inner.find(',') {
                // The part after the first comma must be empty: `{n,}`.
                if brace_inner[pos + 1..].is_empty() {
                    return end_brace - k + 1;
                }
            }
        }
    }
    0
}

/// Prefix-overlap test for literal branches.
#[must_use]
pub fn branches_overlap(branches: &[String]) -> bool {
    for a in 0..branches.len() {
        for b in a + 1..branches.len() {
            let x = &branches[a];
            let y = &branches[b];
            if x == y || x.starts_with(y.as_str()) || y.starts_with(x.as_str()) {
                return true;
            }
        }
    }
    false
}

const META_BRANCH_CHARS: &str = "()[]{}.*+?^$|\\";

/// Whether a branch is a nonempty run of non-meta characters.
#[must_use]
pub fn is_pure_literal_branch(branch: &str) -> bool {
    !branch.is_empty() && !branch.chars().any(|c| META_BRANCH_CHARS.contains(c))
}

/// Split alternation branches at top nesting level.
#[must_use]
pub fn split_top_level_alternations(inner: &[char]) -> Vec<String> {
    let mut branches: Vec<String> = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut k = 0usize;
    while k < inner.len() {
        if let Some(skip_to) = advance_past_escape_or_char_class(inner, k) {
            k = skip_to;
            continue;
        }
        match inner[k] {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                branches.push(inner[start..k].iter().collect());
                start = k + 1;
            }
            _ => {}
        }
        k += 1;
    }
    branches.push(inner[start..].iter().collect());
    branches
}

/// Whether at least two literal branches share a prefix.
#[must_use]
pub fn overlapping_literal_branches(inner: &str) -> bool {
    let chars: Vec<char> = inner.chars().collect();
    let literal_branches: Vec<String> = split_top_level_alternations(&chars)
        .into_iter()
        .filter(|b| is_pure_literal_branch(b))
        .collect();
    literal_branches.len() >= 2 && branches_overlap(&literal_branches)
}

struct QuantifiedGroup {
    start: usize,
    end: usize,
    inner: String,
}

fn iter_quantified_group_bodies_at(
    pattern: &[char],
    base: usize,
    depth: usize,
) -> StructureResult<Vec<QuantifiedGroup>> {
    if depth > MAX_GROUP_NESTING_DEPTH {
        return Err(NestingTooDeep);
    }
    let mut found: Vec<QuantifiedGroup> = Vec::new();
    let mut i = 0usize;
    while i < pattern.len() {
        if pattern[i] != '(' {
            i += 1;
            continue;
        }
        let Some(j) = find_group_end(pattern, i) else {
            i += 1;
            continue;
        };
        let raw_inner: Vec<char> = pattern[i + 1..j - 1].to_vec();
        found.extend(iter_quantified_group_bodies_at(
            &raw_inner,
            base + i + 1,
            depth + 1,
        )?);
        if let Some(inner) = normalize_group_inner(&raw_inner) {
            let inner = unwrap_transparent_wrapper(&inner);
            let qlen = outer_quantifier_len(pattern, j);
            if qlen > 0 {
                found.push(QuantifiedGroup {
                    start: base + i,
                    end: base + j + qlen,
                    inner,
                });
            }
        }
        i = j;
    }
    Ok(found)
}

/// Every quantified group body as `(start, end, inner)` over the source.
pub fn iter_quantified_group_bodies(
    pattern: &str,
) -> StructureResult<Vec<(usize, usize, String)>> {
    let chars: Vec<char> = pattern.chars().collect();
    Ok(
        iter_quantified_group_bodies_at(&chars, 0, 0)?
            .into_iter()
            .map(|g| (g.start, g.end, g.inner))
            .collect(),
    )
}

fn chars_in_range(pattern: &str, start: usize, end: usize) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    chars[start..end.min(chars.len())].iter().collect()
}

fn nested_body_is_unbounded(inner: &str) -> bool {
    let chars: Vec<char> = inner.chars().collect();
    let stripped = strip_escapes_and_char_classes(&chars);
    if stripped.split('|').any(|b| branch_is_unbounded_single(b)) {
        return true;
    }
    overlapping_literal_branches(inner)
}

/// Reference `_detect_nested_unbounded_quantifier`.
#[must_use]
pub fn detect_nested_unbounded_quantifier(pattern: &str) -> Option<String> {
    match iter_quantified_group_bodies(pattern) {
        Ok(bodies) => bodies
            .into_iter()
            .find(|(_, _, inner)| nested_body_is_unbounded(inner))
            .map(|(start, end, _)| chars_in_range(pattern, start, end)),
        Err(NestingTooDeep) => Some(nesting_depth_rejection_reason()),
    }
}

const BROAD_SHORTHAND_ESCAPE_LETTERS: &str = "SWD";

fn is_broad_char_class_inner(inner: &str) -> bool {
    if let Some(excluded) = inner.strip_prefix('^') {
        return !excluded.contains("\\S")
            && !excluded.contains("\\W")
            && !excluded.contains("\\D");
    }
    matches!(inner, "\\s\\S" | "\\S\\s")
}

/// Returns the new index and whether the atom is a broad class.
fn broad_atom_span(pattern: &[char], i: usize) -> (usize, bool) {
    let c = pattern[i];
    let n = pattern.len();
    if c == '\\' && i + 1 < n {
        return (i + 2, BROAD_SHORTHAND_ESCAPE_LETTERS.contains(pattern[i + 1]));
    }
    if c == '[' {
        let j = skip_char_class(pattern, i);
        let inner: String = pattern[i + 1..j - 1].iter().collect();
        return (j, is_broad_char_class_inner(&inner));
    }
    if c == '.' {
        return (i + 1, true);
    }
    (i + 1, false)
}

fn broad_unbounded_run_at(
    pattern: &str,
    depth: usize,
) -> StructureResult<(usize, Vec<String>)> {
    if depth > MAX_GROUP_NESTING_DEPTH {
        return Err(NestingTooDeep);
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut count = 0usize;
    let mut spans: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '(' {
            let Some(j) = find_group_end(&chars, i) else {
                i += 1;
                continue;
            };
            let raw: Vec<char> = chars[i + 1..j - 1].to_vec();
            if let Some(inner) = normalize_group_inner(&raw) {
                let inner_chars: Vec<char> = inner.chars().collect();
                let mut best: Option<(usize, Vec<String>)> = None;
                for branch in split_top_level_alternations(&inner_chars) {
                    let result = broad_unbounded_run_at(&branch, depth + 1)?;
                    let better = match &best {
                        None => true,
                        Some((best_count, _)) => result.0 > *best_count,
                    };
                    if better {
                        best = Some(result);
                    }
                }
                if let Some((best_count, best_spans)) = best {
                    count += best_count;
                    spans.extend(best_spans);
                }
            }
            i = j;
            continue;
        }
        let (atom_end, is_broad) = broad_atom_span(&chars, i);
        if is_broad && outer_quantifier_len(&chars, atom_end) > 0 {
            count += 1;
            spans.push(chars[i..atom_end].iter().collect());
        }
        i = atom_end;
    }
    Ok((count, spans))
}

/// Reference `_detect_adjacent_broad_unbounded_quantifiers`.
#[must_use]
pub fn detect_adjacent_broad_unbounded_quantifiers(pattern: &str) -> Option<String> {
    let (count, spans) = match broad_unbounded_run_at(pattern, 0) {
        Ok(result) => result,
        Err(NestingTooDeep) => return Some(nesting_depth_rejection_reason()),
    };
    if count >= 2 {
        let joined = spans
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(" and ");
        return Some(joined);
    }
    None
}
