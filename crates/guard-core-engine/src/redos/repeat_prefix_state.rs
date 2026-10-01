//! Prefix-walk state machine shared by the repeat-prefix machinery.
//!
//! Port of the reference `_redos_repeat_prefix_state.py`.

use super::intervals::IntervalSet;
use super::parse_slots::node_intervals;
use super::timeout::BuilderTimeout;

/// Reference `_REPEAT_PREFIX_BUDGET`.
pub const REPEAT_PREFIX_BUDGET: usize = 24000;
/// Reference `_REPEAT_PREFIX_STATE_LIMIT`.
pub const REPEAT_PREFIX_STATE_LIMIT: usize = 1024;
/// Reference `_PREFIX_WALK_STATE_LIMIT`.
pub const PREFIX_WALK_STATE_LIMIT: usize = 16384;
/// Reference `_PREFIX_WALK_TEXT_BUDGET`.
pub const PREFIX_WALK_TEXT_BUDGET: usize = 2_000_000;

/// The reference `_RepeatPrefixState`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepeatPrefixState {
    pub text: String,
    pub pending: String,
    pub excluded: IntervalSet,
    pub forbidden: Vec<String>,
    pub captures: Vec<(u32, String)>,
    pub last_atom: Option<IntervalSet>,
}

impl Default for RepeatPrefixState {
    fn default() -> Self {
        Self {
            text: String::new(),
            pending: String::new(),
            excluded: IntervalSet::empty(),
            forbidden: Vec::new(),
            captures: Vec::new(),
            last_atom: None,
        }
    }
}

/// Reference `_state_text_size`.
#[must_use]
pub fn state_text_size(state: &RepeatPrefixState) -> usize {
    state.text.len()
        + state.pending.len()
        + state.forbidden.iter().map(String::len).sum::<usize>()
        + state
            .captures
            .iter()
            .map(|(_group, value)| value.len())
            .sum::<usize>()
}

fn merge_pending(left: &str, right: &str) -> Option<String> {
    let common = left.len().min(right.len());
    if left.as_bytes()[..common] != right.as_bytes()[..common] {
        return None;
    }
    Some(
        if left.len() >= right.len() {
            left
        } else {
            right
        }
        .to_owned(),
    )
}

fn remaining_forbidden(words: &[String], piece: &str) -> Option<Vec<String>> {
    for word in words {
        if piece.starts_with(word.as_str()) {
            return None;
        }
    }
    Some(
        words
            .iter()
            .filter(|word| word.starts_with(piece))
            .map(|word| word[piece.len()..].to_owned())
            .collect(),
    )
}

/// Reference `_consume_piece`.
pub fn consume_piece(
    state: &RepeatPrefixState,
    piece: &str,
) -> Result<Option<RepeatPrefixState>, BuilderTimeout> {
    if piece.is_empty() {
        return Ok(Some(state.clone()));
    }
    let Some(first) = piece.chars().next() else {
        return Ok(Some(state.clone()));
    };
    if state.excluded.contains(u32::from(first)) {
        return Ok(None);
    }
    let pending: Vec<char> = state.pending.chars().collect();
    let piece_chars: Vec<char> = piece.chars().collect();
    let common = pending.len().min(piece_chars.len());
    if pending[..common] != piece_chars[..common] {
        return Ok(None);
    }
    let Some(forbidden) = remaining_forbidden(&state.forbidden, piece) else {
        return Ok(None);
    };
    if state.text.len() + piece.len() > REPEAT_PREFIX_BUDGET {
        return Err(BuilderTimeout(
            "Pattern validation repeat-prefix length budget exceeded".into(),
        ));
    }
    let last = piece_chars.last().copied().unwrap_or(first);
    Ok(Some(RepeatPrefixState {
        text: format!("{}{piece}", state.text),
        pending: pending[common..].iter().collect(),
        excluded: IntervalSet::empty(),
        forbidden,
        captures: state.captures.clone(),
        last_atom: Some(IntervalSet::single(u32::from(last))),
    }))
}

/// Reference `_consume_atom`.
pub fn consume_atom(
    state: &RepeatPrefixState,
    intervals: &IntervalSet,
) -> Result<Option<RepeatPrefixState>, BuilderTimeout> {
    let mut available = intervals.difference(&state.excluded);
    for word in &state.forbidden {
        let Some(first) = word.chars().next() else {
            continue;
        };
        if word.chars().count() == 1 {
            available = available.difference(&IntervalSet::single(u32::from(first)));
        }
    }
    let member = match state.pending.chars().next() {
        Some(c) => u32::from(c),
        None => match available.first_member() {
            Some(member) => member,
            None => return Ok(None),
        },
    };
    if !available.contains(member) {
        return Ok(None);
    }
    let Some(consumed) = consume_piece(
        state,
        &char::from_u32(member).map(String::from).unwrap_or_default(),
    )?
    else {
        return Ok(None);
    };
    Ok(Some(RepeatPrefixState {
        last_atom: Some(available),
        ..consumed
    }))
}

/// Reference `_capture_state`.
#[must_use]
pub fn capture_state(
    state: &RepeatPrefixState,
    group: Option<u32>,
    start: usize,
) -> RepeatPrefixState {
    let Some(group) = group else {
        return state.clone();
    };
    let mut captures: Vec<(u32, String)> = state.captures.clone();
    captures.retain(|(existing, _)| *existing != group);
    captures.push((group, state.text[start.min(state.text.len())..].to_owned()));
    captures.sort_by_key(|(existing, _)| *existing);
    RepeatPrefixState {
        captures,
        ..state.clone()
    }
}

/// Reference `_positive_assertion`.
#[must_use]
pub fn positive_assertion(
    behind: bool,
    witnesses: &[RepeatPrefixState],
    state: &RepeatPrefixState,
) -> Vec<RepeatPrefixState> {
    if behind {
        return witnesses
            .iter()
            .map(|witness| {
                let text = if witness.text.is_empty() {
                    state.text.clone()
                } else {
                    let cut = state.text.len().saturating_sub(witness.text.len());
                    format!("{}{}", &state.text[..cut], witness.text)
                };
                let mut captures: Vec<(u32, String)> = state.captures.clone();
                for (group, value) in &witness.captures {
                    captures.retain(|(existing, _)| existing != group);
                    captures.push((*group, value.clone()));
                }
                captures.sort_by_key(|(group, _)| *group);
                RepeatPrefixState {
                    text,
                    captures,
                    ..state.clone()
                }
            })
            .collect();
    }
    witnesses
        .iter()
        .filter_map(|witness| {
            merge_pending(&state.pending, &witness.text).map(|pending| {
                let mut captures: Vec<(u32, String)> = state.captures.clone();
                for (group, value) in &witness.captures {
                    captures.retain(|(existing, _)| existing != group);
                    captures.push((*group, value.clone()));
                }
                captures.sort_by_key(|(group, _)| *group);
                RepeatPrefixState {
                    pending,
                    captures,
                    ..state.clone()
                }
            })
        })
        .collect()
}

/// Reference `_negative_assertion`.
#[must_use]
pub fn negative_assertion(
    body: &[super::ast::Op],
    flags: super::ast::Flags,
    witnesses: &[RepeatPrefixState],
    state: &RepeatPrefixState,
) -> Vec<RepeatPrefixState> {
    if body.is_empty() {
        return Vec::new();
    }
    if body.len() == 1 && body[0].is_pairing() {
        return vec![RepeatPrefixState {
            excluded: state
                .excluded
                .union(&node_intervals(&body[0], flags)),
            ..state.clone()
        }];
    }
    let words: Vec<String> = witnesses
        .iter()
        .filter(|witness| !witness.text.is_empty())
        .map(|witness| witness.text.clone())
        .collect();
    let mut forbidden = state.forbidden.clone();
    forbidden.extend(words);
    vec![RepeatPrefixState {
        forbidden,
        ..state.clone()
    }]
}
