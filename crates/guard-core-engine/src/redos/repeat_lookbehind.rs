//! Negative-lookbehind handling for the prefix walk.
//!
//! Port of the reference `_redos_repeat_lookbehind.py`.

use super::intervals::IntervalSet;
use super::parse_slots::node_intervals;
use super::repeat_prefix_state::{RepeatPrefixState, REPEAT_PREFIX_STATE_LIMIT};
use super::timeout::BuilderTimeout;

fn check_mutation_budget(
    state: &RepeatPrefixState,
    count: usize,
) -> Result<(), BuilderTimeout> {
    if !state.captures.is_empty() {
        return Err(BuilderTimeout(
            "Pattern validation cannot resolve capture-dependent lookbehind".into(),
        ));
    }
    if count > REPEAT_PREFIX_STATE_LIMIT {
        return Err(BuilderTimeout(
            "Pattern validation lookbehind state budget exceeded".into(),
        ));
    }
    Ok(())
}

fn forbidden_final_atom(
    body: &[super::ast::Op],
    flags: super::ast::Flags,
) -> Option<IntervalSet> {
    if body.len() != 1 || !body[0].is_pairing() {
        return None;
    }
    Some(node_intervals(&body[0], flags))
}

fn negative_lookbehind(
    forbidden: &IntervalSet,
    state: &RepeatPrefixState,
) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
    let last = state
        .text
        .chars()
        .last()
        .map(|c| u32::from(c))
        .unwrap_or(0);
    if state.text.is_empty() || !forbidden.contains(last) {
        return Ok(vec![state.clone()]);
    }
    check_mutation_budget(state, 0)?;
    let available = state
        .last_atom
        .clone()
        .unwrap_or_else(|| IntervalSet::single(last))
        .difference(forbidden);
    let Some(member) = available.first_member() else {
        return Ok(Vec::new());
    };
    let replacement = char::from_u32(member).unwrap_or('\0');
    let mut text: Vec<char> = state.text.chars().collect();
    text.pop();
    text.push(replacement);
    Ok(vec![RepeatPrefixState {
        text: text.into_iter().collect(),
        last_atom: Some(available),
        ..state.clone()
    }])
}

fn matching_witness_width(text: &str, witnesses: &[RepeatPrefixState]) -> usize {
    witnesses
        .iter()
        .filter(|witness| !witness.text.is_empty() && text.ends_with(&witness.text))
        .map(|witness| witness.text.len())
        .max()
        .unwrap_or(0)
}

fn changed_prefixes(
    state: &RepeatPrefixState,
    width: usize,
    alphabet: &[String],
) -> Vec<RepeatPrefixState> {
    let text: Vec<char> = state.text.chars().collect();
    let len = text.len();
    let mut result = Vec::new();
    // Positions from len-1 down to len-width (inclusive).
    let positions: Vec<usize> = (0..len).rev().take(width).collect();
    for i in positions {
        for char in alphabet {
            let mut candidate = text.clone();
            let chars: Vec<char> = char.chars().collect();
            if chars.len() != 1 || chars[0] == text[i] {
                continue;
            }
            candidate[i] = chars[0];
            result.push(RepeatPrefixState {
                text: candidate.into_iter().collect(),
                ..state.clone()
            });
        }
    }
    result
}

fn lookbehind_alternatives(
    state: &RepeatPrefixState,
    witnesses: &[RepeatPrefixState],
    alphabet: &[String],
) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
    let width = matching_witness_width(&state.text, witnesses);
    if width == 0 {
        return Ok(vec![state.clone()]);
    }
    check_mutation_budget(state, width * alphabet.len())?;
    Ok(changed_prefixes(state, width, alphabet))
}

/// Reference `_walk_negative_behind`.
pub fn walk_negative_behind(
    body: &[super::ast::Op],
    flags: super::ast::Flags,
    witnesses: &[RepeatPrefixState],
    states: &[RepeatPrefixState],
    alphabet: &[String],
) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
    let Some(forbidden) = forbidden_final_atom(body, flags) else {
        let mut result = Vec::new();
        for state in states {
            result.extend(lookbehind_alternatives(state, witnesses, alphabet)?);
        }
        return Ok(result);
    };
    let mut result = Vec::new();
    for state in states {
        result.extend(negative_lookbehind(&forbidden, state)?);
    }
    Ok(result)
}
