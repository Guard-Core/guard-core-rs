//! Negative-lookbehind handling for the prefix walk.
//!
//! Port of the reference `_redos_repeat_lookbehind.py`.

use super::intervals::IntervalSet;
use super::parse_slots::node_intervals;
use super::repeat_prefix_state::{REPEAT_PREFIX_STATE_LIMIT, RepeatPrefixState};
use super::timeout::BuilderTimeout;

fn check_mutation_budget(state: &RepeatPrefixState, count: usize) -> Result<(), BuilderTimeout> {
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

fn forbidden_final_atom(body: &[super::ast::Op], flags: super::ast::Flags) -> Option<IntervalSet> {
    if body.len() != 1 || !body[0].is_pairing() {
        return None;
    }
    Some(node_intervals(&body[0], flags))
}

fn negative_lookbehind(
    forbidden: &IntervalSet,
    state: &RepeatPrefixState,
) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
    let last = state.text.chars().last().map(u32::from).unwrap_or(0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::{Flags, Op};

    fn witnesses(texts: &[&str]) -> Vec<RepeatPrefixState> {
        texts
            .iter()
            .map(|text| RepeatPrefixState {
                text: (*text).to_owned(),
                ..RepeatPrefixState::default()
            })
            .collect()
    }

    #[test]
    fn forbidden_final_atom_requires_a_single_pairing_body() {
        assert_eq!(
            forbidden_final_atom(&[Op::Literal(u32::from('x'))], Flags::default()),
            Some(IntervalSet::single(u32::from('x')))
        );
        assert_eq!(forbidden_final_atom(&[], Flags::default()), None);
        assert_eq!(
            forbidden_final_atom(&[Op::Literal(97), Op::Literal(98)], Flags::default()),
            None
        );
        assert_eq!(
            forbidden_final_atom(&[Op::GroupRef(1)], Flags::default()),
            None
        );
    }

    #[test]
    fn negative_lookbehind_keeps_a_state_whose_tail_is_allowed() {
        let forbidden = IntervalSet::single(u32::from('x'));
        let state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        let result = negative_lookbehind(&forbidden, &state).expect("no budget error");
        assert_eq!(result, vec![state]);
    }

    #[test]
    fn negative_lookbehind_empty_text_is_untouched() {
        let forbidden = IntervalSet::single(u32::from('x'));
        let result = negative_lookbehind(&forbidden, &RepeatPrefixState::default())
            .expect("no budget error");
        assert_eq!(result.len(), 1);
        assert!(result[0].text.is_empty());
    }

    #[test]
    fn negative_lookbehind_swaps_the_last_character_via_last_atom() {
        let forbidden = IntervalSet::single(u32::from('b'));
        let state = RepeatPrefixState {
            text: "ab".into(),
            last_atom: Some(IntervalSet::new(&[(u32::from('a'), u32::from('b'))])),
            ..RepeatPrefixState::default()
        };
        let result = negative_lookbehind(&forbidden, &state).expect("no budget error");
        assert_eq!(result[0].text, "aa");
        assert_eq!(
            result[0].last_atom,
            Some(IntervalSet::single(u32::from('a')))
        );
    }

    #[test]
    fn negative_lookbehind_without_last_atom_falls_back_to_the_character() {
        let forbidden = IntervalSet::single(u32::from('b'));
        let state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        // The fallback atom is the character itself; with the forbidden
        // set covering it there is no replacement left.
        let result = negative_lookbehind(&forbidden, &state).expect("no budget error");
        assert!(result.is_empty());
    }

    #[test]
    fn negative_lookbehind_dies_when_no_replacement_exists() {
        let forbidden = IntervalSet::single(u32::from('b'));
        let state = RepeatPrefixState {
            text: "ab".into(),
            last_atom: Some(IntervalSet::single(u32::from('b'))),
            ..RepeatPrefixState::default()
        };
        let result = negative_lookbehind(&forbidden, &state).expect("no budget error");
        assert!(result.is_empty());
    }

    #[test]
    fn negative_lookbehind_rejects_capture_dependence() {
        let forbidden = IntervalSet::single(u32::from('b'));
        let mut state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        state.captures = vec![(1, "b".into())];
        let error = negative_lookbehind(&forbidden, &state).expect_err("budget error");
        assert_eq!(
            error.0,
            "Pattern validation cannot resolve capture-dependent lookbehind"
        );
    }

    #[test]
    fn matching_witness_width_takes_the_longest_suffix_witness() {
        let states = witnesses(&["bc", "abc", "xyz"]);
        assert_eq!(matching_witness_width("zabc", &states), 3);
        assert_eq!(matching_witness_width("nope", &states), 0);
    }

    #[test]
    fn changed_prefixes_swaps_every_position_in_the_width() {
        let state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        let alphabet = vec!["x".to_owned(), "y".to_owned()];
        let result = changed_prefixes(&state, 2, &alphabet);
        assert_eq!(result.len(), 4);
        let texts: Vec<String> = result.iter().map(|s| s.text.clone()).collect();
        assert!(texts.contains(&"xb".to_owned()));
        assert!(texts.contains(&"yb".to_owned()));
        assert!(texts.contains(&"ax".to_owned()));
        assert!(texts.contains(&"ay".to_owned()));
    }

    #[test]
    fn changed_prefixes_skips_multi_char_and_identical_alphabet_entries() {
        let state = RepeatPrefixState {
            text: "a".into(),
            ..RepeatPrefixState::default()
        };
        let alphabet = vec!["a".to_owned(), "xy".to_owned()];
        assert!(changed_prefixes(&state, 1, &alphabet).is_empty());
    }

    #[test]
    fn lookbehind_alternatives_expand_when_a_witness_matches() {
        let state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        let states = witnesses(&["ab"]);
        // One alternative per position in the witness width: the tail
        // first, then the head.
        let result = lookbehind_alternatives(&state, &states, &["x".to_owned()]).expect("budget");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].text, "ax");
        assert_eq!(result[1].text, "xb");
    }

    #[test]
    fn lookbehind_alternatives_keep_the_state_without_a_witness_match() {
        let state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        let result = lookbehind_alternatives(&state, &[], &["x".to_owned()]).expect("budget");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "ab");
    }

    #[test]
    fn lookbehind_alternatives_enforce_the_state_budget() {
        let state = RepeatPrefixState {
            text: "a".repeat(REPEAT_PREFIX_STATE_LIMIT + 1),
            ..RepeatPrefixState::default()
        };
        let alphabet: Vec<String> = (0..=REPEAT_PREFIX_STATE_LIMIT)
            .map(|i| format!("x{i}"))
            .collect();
        let error = lookbehind_alternatives(&state, &witnesses(&["a"]), &alphabet)
            .expect_err("budget exceeded");
        assert_eq!(
            error.0,
            "Pattern validation lookbehind state budget exceeded"
        );
    }

    #[test]
    fn walk_negative_behind_uses_the_forbidden_atom_path() {
        let body = [Op::Literal(u32::from('b'))];
        let state = RepeatPrefixState {
            text: "ab".into(),
            last_atom: Some(IntervalSet::new(&[(97, 98)])),
            ..RepeatPrefixState::default()
        };
        let result =
            walk_negative_behind(&body, Flags::default(), &[], &[state], &[]).expect("budget");
        assert_eq!(result[0].text, "aa");
    }

    #[test]
    fn walk_negative_behind_falls_back_to_alternatives_for_non_pairing_bodies() {
        let body = [Op::GroupRef(1)];
        let state = RepeatPrefixState {
            text: "ab".into(),
            ..RepeatPrefixState::default()
        };
        let result = walk_negative_behind(
            &body,
            Flags::default(),
            &witnesses(&["ab"]),
            &[state],
            &["x".to_owned()],
        )
        .expect("budget");
        // The tail position changes first.
        assert_eq!(result[0].text, "ax");
        assert_eq!(result[1].text, "xb");
    }
}
