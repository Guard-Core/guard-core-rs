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
            excluded: state.excluded.union(&node_intervals(&body[0], flags)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::{Flags, Op};

    fn state(text: &str) -> RepeatPrefixState {
        RepeatPrefixState {
            text: text.to_owned(),
            ..RepeatPrefixState::default()
        }
    }

    #[test]
    fn consume_piece_appends_text_and_tracks_the_last_atom() {
        let consumed = consume_piece(&state("ab"), "cd").expect("no budget error");
        let consumed = consumed.expect("piece consumed");
        assert_eq!(consumed.text, "abcd");
        assert_eq!(
            consumed.last_atom,
            Some(IntervalSet::single(u32::from('d')))
        );
    }

    #[test]
    fn consume_piece_empty_returns_the_state() {
        let original = state("ab");
        let consumed = consume_piece(&original, "").expect("no budget error");
        assert_eq!(consumed, Some(original));
    }

    #[test]
    fn consume_piece_rejects_an_excluded_first_character() {
        let mut excluded = state("ab");
        excluded.excluded = IntervalSet::single(u32::from('x'));
        assert_eq!(
            consume_piece(&excluded, "xy").expect("no budget error"),
            None
        );
    }

    #[test]
    fn consume_piece_rejects_a_pending_mismatch() {
        let mut pending = state("ab");
        pending.pending = "xy".into();
        assert_eq!(
            consume_piece(&pending, "ax").expect("no budget error"),
            None
        );
    }

    #[test]
    fn consume_piece_consumes_a_matching_pending_prefix() {
        let mut pending = state("ab");
        pending.pending = "cd".into();
        let consumed = consume_piece(&pending, "c").expect("no budget error");
        let consumed = consumed.expect("prefix consumed");
        assert_eq!(consumed.text, "abc");
        assert_eq!(consumed.pending, "d");
    }

    #[test]
    fn consume_piece_forbidden_prefix_kills_the_state() {
        // The kill condition is `piece.startswith(word)`: the consumed
        // piece covers the whole forbidden word.
        let mut forbidden = state("ab");
        forbidden.forbidden = vec!["xyz".into()];
        assert_eq!(
            consume_piece(&forbidden, "xyz").expect("no budget error"),
            None
        );
    }

    #[test]
    fn consume_piece_forbidden_word_survivors_drop_the_consumed_prefix() {
        let mut forbidden = state("");
        forbidden.forbidden = vec!["abcd".into()];
        let consumed = consume_piece(&forbidden, "ab").expect("no budget error");
        let consumed = consumed.expect("prefix consumed");
        assert_eq!(consumed.forbidden, vec!["cd".to_owned()]);
    }

    #[test]
    fn consume_piece_over_the_length_budget_is_an_error() {
        let mut long = state("");
        long.text = "a".repeat(REPEAT_PREFIX_BUDGET);
        let error = consume_piece(&long, "b").expect_err("budget exceeded");
        assert_eq!(
            error.0,
            "Pattern validation repeat-prefix length budget exceeded"
        );
    }

    #[test]
    fn consume_atom_picks_the_first_available_member() {
        let intervals = IntervalSet::new(&[(u32::from('a'), u32::from('c'))]);
        let consumed = consume_atom(&state(""), &intervals)
            .expect("no budget error")
            .expect("atom consumed");
        assert_eq!(consumed.text, "a");
        assert_eq!(consumed.last_atom, Some(intervals));
    }

    #[test]
    fn consume_atom_honors_pending_before_availability() {
        let intervals = IntervalSet::new(&[(u32::from('a'), u32::from('z'))]);
        let mut pending = state("");
        pending.pending = "q".into();
        let consumed = consume_atom(&pending, &intervals)
            .expect("no budget error")
            .expect("atom consumed");
        assert_eq!(consumed.text, "q");
    }

    #[test]
    fn consume_atom_returns_none_when_everything_is_excluded() {
        let intervals = IntervalSet::single(u32::from('a'));
        let mut excluded = state("");
        excluded.excluded = IntervalSet::single(u32::from('a'));
        assert_eq!(
            consume_atom(&excluded, &intervals).expect("no budget error"),
            None
        );
    }

    #[test]
    fn consume_atom_filters_single_char_forbidden_words() {
        let intervals = IntervalSet::new(&[(u32::from('a'), u32::from('b'))]);
        let mut forbidden = state("");
        forbidden.forbidden = vec!["a".into()];
        let consumed = consume_atom(&forbidden, &intervals)
            .expect("no budget error")
            .expect("atom consumed");
        assert_eq!(consumed.text, "b");
    }

    #[test]
    fn capture_state_ignores_anonymous_groups() {
        let original = state("ab");
        assert_eq!(capture_state(&original, None, 0), original);
    }

    #[test]
    fn capture_state_records_the_group_body() {
        let captured = capture_state(&state("abcd"), Some(2), 1);
        assert_eq!(captured.captures, vec![(2, "bcd".to_owned())]);
    }

    #[test]
    fn capture_state_replaces_an_existing_group_number() {
        let mut original = state("xyz");
        original.captures = vec![(1, "old".into())];
        let captured = capture_state(&original, Some(1), 1);
        assert_eq!(captured.captures, vec![(1, "yz".to_owned())]);
    }

    #[test]
    fn positive_assertion_lookahead_merges_pending() {
        let witness = state("bc");
        let mut base = state("a");
        base.pending = "b".into();
        let result = positive_assertion(false, &[witness], &base);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pending, "bc");
    }

    #[test]
    fn positive_assertion_lookahead_drops_a_disjoint_pending() {
        let witness = state("bc");
        let mut base = state("a");
        base.pending = "z".into();
        let result = positive_assertion(false, &[witness], &base);
        assert!(result.is_empty());
    }

    #[test]
    fn positive_assertion_lookahead_drops_incompatible_witnesses() {
        let witness = state("bc");
        let mut base = state("a");
        base.pending = "x".into();
        let result = positive_assertion(false, &[witness], &base);
        assert!(result.is_empty());
    }

    #[test]
    fn positive_assertion_lookbehind_swaps_the_witness_text() {
        // The reference keeps the prefix before the witness span.
        let witness = state("bc");
        let result = positive_assertion(true, &[witness], &state("abc"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "abc");
    }

    #[test]
    fn positive_assertion_merges_witness_captures() {
        let mut witness = state("b");
        witness.captures = vec![(3, "b".into())];
        let result = positive_assertion(false, &[witness], &state("a"));
        assert_eq!(result[0].captures, vec![(3, "b".to_owned())]);
    }

    #[test]
    fn negative_assertion_empty_body_dies() {
        let result = negative_assertion(&[], Flags::default(), &[], &state("a"));
        assert!(result.is_empty());
    }

    #[test]
    fn negative_assertion_pairing_body_excludes_the_intervals() {
        let mut base = state("a");
        base.excluded = IntervalSet::single(1);
        let result =
            negative_assertion(&[Op::Literal(u32::from('x'))], Flags::default(), &[], &base);
        assert_eq!(result.len(), 1);
        assert!(result[0].excluded.contains(u32::from('x')));
    }

    #[test]
    fn negative_assertion_non_pairing_body_forbids_witness_words() {
        let witness = state("xy");
        let mut base = state("a");
        base.forbidden = vec!["old".into()];
        let result = negative_assertion(
            &[Op::GroupRef(1)],
            Flags::default(),
            std::slice::from_ref(&witness),
            &base,
        );
        assert_eq!(result[0].forbidden, vec!["old".to_owned(), "xy".to_owned()]);
    }

    #[test]
    fn state_text_size_sums_every_text_field() {
        let mut sized = state("abc");
        sized.pending = "de".into();
        sized.forbidden = vec!["fgh".into(), "i".into()];
        sized.captures = vec![(1, "jk".into())];
        assert_eq!(state_text_size(&sized), 3 + 2 + 4 + 2);
    }
}
