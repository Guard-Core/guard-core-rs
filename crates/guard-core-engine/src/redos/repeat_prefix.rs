//! The prefix walk: consumes parsed ops from the empty state and yields
//! the reachable prefix states, recording reaching prefixes for repeated
//! bodies.
//!
//! Port of the reference `_redos_repeat_prefix.py` (`_PrefixWalk` and
//! `_repeat_reaching_prefixes`).

use std::collections::HashSet;
use std::time::Instant;

use super::ast::{self, Flags, Op};
use super::parse_slots::node_intervals;
use super::prefix_history::{contains_repeat, optional_states_are_equivalent, suffix_history};
use super::repeat_alphabet::repeat_alphabet_fills;
use super::repeat_lookbehind::walk_negative_behind;
use super::repeat_prefix_state::{
    PREFIX_WALK_STATE_LIMIT, PREFIX_WALK_TEXT_BUDGET, REPEAT_PREFIX_STATE_LIMIT, RepeatPrefixState,
    capture_state, consume_atom, consume_piece, positive_assertion, state_text_size,
};
use super::timeout::BuilderTimeout;

pub(crate) type RepeatCollector<'a> =
    &'a mut dyn FnMut(&[Op], Flags, &[RepeatPrefixState]) -> Result<(), BuilderTimeout>;

pub(crate) fn check_deadline(deadline: Option<Instant>) -> Result<(), BuilderTimeout> {
    if let Some(deadline) = deadline
        && Instant::now() >= deadline
    {
        return Err(BuilderTimeout(
            "Pattern validation repeat-prefix construction exceeded its deadline".into(),
        ));
    }
    Ok(())
}

pub(crate) fn unique_states(
    states: Vec<RepeatPrefixState>,
) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
    let mut unique: Vec<RepeatPrefixState> = Vec::with_capacity(states.len());
    let mut seen: HashSet<RepeatPrefixState> = HashSet::with_capacity(states.len());
    for state in states {
        if seen.insert(state.clone()) {
            unique.push(state);
        }
    }
    if unique.len() > PREFIX_WALK_STATE_LIMIT {
        return Err(BuilderTimeout(
            "Pattern validation repeat-prefix state budget exceeded".into(),
        ));
    }
    if unique.iter().map(state_text_size).sum::<usize>() > PREFIX_WALK_TEXT_BUDGET {
        return Err(BuilderTimeout(
            "Pattern validation repeat-prefix text budget exceeded".into(),
        ));
    }
    Ok(unique)
}

fn assertion_witnesses(
    body: &[Op],
    flags: Flags,
    deadline: Option<Instant>,
) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
    let mut unused_prefixes = Vec::new();
    let mut walker = PrefixWalk {
        flags,
        prefixes: &mut unused_prefixes,
        deadline,
        collect: false,
        alphabet: Vec::new(),
        repeat_collector: None,
        canonical_optionals: false,
        require_reachable: false,
    };
    let states = walker.walk(body, vec![RepeatPrefixState::default()], false)?;
    if states.iter().any(|state| {
        !state.pending.is_empty() || !state.forbidden.is_empty() || !state.excluded.is_empty()
    }) {
        return Err(BuilderTimeout(
            "Pattern validation cannot resolve nested assertion constraints".into(),
        ));
    }
    Ok(states)
}

/// The reference `_PrefixWalk` as a context struct.
pub(crate) struct PrefixWalk<'a> {
    pub flags: Flags,
    pub prefixes: &'a mut Vec<String>,
    pub deadline: Option<Instant>,
    pub collect: bool,
    pub alphabet: Vec<String>,
    pub repeat_collector: Option<RepeatCollector<'a>>,
    pub canonical_optionals: bool,
    pub require_reachable: bool,
}

impl PrefixWalk<'_> {
    fn check_remaining_repeats(&self, items: &[Op]) -> Result<(), BuilderTimeout> {
        if self.require_reachable && contains_repeat(items) {
            return Err(BuilderTimeout(
                "Pattern validation cannot resolve repeat-site prefixes".into(),
            ));
        }
        Ok(())
    }

    fn atoms(
        &self,
        op: &Op,
        states: Vec<RepeatPrefixState>,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let intervals = node_intervals(op, self.flags);
        let mut result = Vec::with_capacity(states.len());
        for state in states {
            if let Some(next_state) = consume_atom(&state, &intervals)? {
                result.push(next_state);
            }
        }
        Ok(result)
    }

    fn record_prefixes(
        &mut self,
        high: Option<u32>,
        states: &[RepeatPrefixState],
    ) -> Result<(), BuilderTimeout> {
        if self.collect && high.is_none_or(|high| high > 1) {
            for state in states {
                self.prefixes
                    .push(format!("{}{}", state.text, state.pending));
            }
            if self.prefixes.len() > REPEAT_PREFIX_STATE_LIMIT * 4 {
                return Err(BuilderTimeout(
                    "Pattern validation repeat-prefix candidate budget exceeded".into(),
                ));
            }
        }
        Ok(())
    }

    fn repeat(
        &mut self,
        low: u32,
        high: Option<u32>,
        body: &[Op],
        states: Vec<RepeatPrefixState>,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        self.record_prefixes(high, &states)?;
        if high.is_none_or(|high| high > 1)
            && let Some(collector) = self.repeat_collector.as_mut()
        {
            collector(body, self.flags, &states)?;
        }
        if low == 0 && high.is_none_or(|high| high > 0) {
            let expanded = self.walk(body, states.clone(), history_observable)?;
            if self.canonical_optionals
                && optional_states_are_equivalent(body, &states, history_observable)
            {
                return Ok(states);
            }
            let mut all = states.clone();
            all.extend(expanded.clone());
            let combined = unique_states(all)?;
            let remaining = match high {
                None => u64::MAX,
                Some(high) => u64::from(high.max(1) - 1),
            };
            return self.pending_repeats(body, combined, expanded, remaining, history_observable);
        }
        let mut current = states;
        for _ in 0..low {
            check_deadline(self.deadline)?;
            let previous = current.clone();
            current = self.walk(body, current, history_observable)?;
            if current == previous || current.is_empty() {
                break;
            }
        }
        let remaining = match high {
            None => u64::MAX,
            Some(high) => u64::from(high.saturating_sub(low)),
        };
        let snapshot = current.clone();
        self.pending_repeats(body, current, snapshot, remaining, history_observable)
    }

    fn pending_repeats(
        &mut self,
        body: &[Op],
        result: Vec<RepeatPrefixState>,
        frontier: Vec<RepeatPrefixState>,
        remaining: u64,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let mut result = result;
        let mut frontier = frontier;
        let mut remaining = remaining;
        while remaining > 0 {
            let pending: Vec<RepeatPrefixState> = frontier
                .iter()
                .filter(|state| !state.pending.is_empty())
                .cloned()
                .collect();
            if pending.is_empty() {
                break;
            }
            check_deadline(self.deadline)?;
            frontier = self.walk(body, pending.clone(), history_observable)?;
            let mut all = result.clone();
            all.extend(frontier.clone());
            result = unique_states(all)?;
            if frontier == pending {
                break;
            }
            remaining -= 1;
        }
        Ok(result)
    }

    fn branch(
        &mut self,
        alternatives: &[Vec<Op>],
        states: Vec<RepeatPrefixState>,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let mut result: Vec<RepeatPrefixState> = Vec::new();
        for alternative in alternatives {
            let walked = self.walk(alternative, states.clone(), history_observable)?;
            let mut all = result;
            all.extend(walked);
            result = unique_states(all)?;
        }
        Ok(result)
    }

    fn group(
        &mut self,
        group: Option<u32>,
        add: Flags,
        del: Flags,
        body: &[Op],
        states: Vec<RepeatPrefixState>,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        // The reference builds a child walker that differs only in flags;
        // every other field (prefixes, deadline, collector) is shared, so
        // mutating in place and restoring is behaviorally identical.
        let saved_flags = self.flags;
        self.flags.apply_delta(&add, &del);
        let mut result: Vec<RepeatPrefixState> = Vec::new();
        for state in states {
            let start = state.text.len();
            let walked = self.walk(body, vec![state], history_observable)?;
            for next_state in walked {
                result.push(capture_state(&next_state, group, start));
            }
        }
        self.flags = saved_flags;
        Ok(result)
    }

    fn assertion(
        &mut self,
        behind: bool,
        negated: bool,
        body: &[Op],
        states: Vec<RepeatPrefixState>,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let witnesses = assertion_witnesses(body, self.flags, self.deadline)?;
        if !negated {
            let mut result = Vec::new();
            for state in &states {
                result.extend(positive_assertion(behind, &witnesses, state));
            }
            return Ok(result);
        }
        if behind {
            return walk_negative_behind(body, self.flags, &witnesses, &states, &self.alphabet);
        }
        let mut result = Vec::new();
        for state in &states {
            result.extend(super::repeat_prefix_state::negative_assertion(
                body, self.flags, &witnesses, state,
            ));
        }
        Ok(result)
    }

    fn backreference(
        &self,
        group: u32,
        states: Vec<RepeatPrefixState>,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let mut result = Vec::new();
        for state in states {
            let captured = state
                .captures
                .iter()
                .find(|(existing, _)| *existing == group)
                .map(|(_, value)| value.clone());
            if let Some(captured) = captured
                && let Some(next_state) = consume_piece(&state, &captured)?
            {
                result.push(next_state);
            }
        }
        Ok(result)
    }

    fn node(
        &mut self,
        op: &Op,
        states: Vec<RepeatPrefixState>,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        match op {
            Op::Literal(_) | Op::NotLiteral(_) | Op::In(_) | Op::Any | Op::Category(_) => {
                self.atoms(op, states)
            }
            Op::Repeat {
                kind: _,
                low,
                high,
                body,
            } => self.repeat(*low, *high, body, states, history_observable),
            Op::GroupRef(group) => self.backreference(*group, states),
            Op::Branch(alternatives) => self.branch(alternatives, states, history_observable),
            Op::SubPattern {
                group,
                add,
                del,
                body,
            } => self.group(*group, *add, *del, body, states, history_observable),
            Op::GroupRefExists { group, yes, no } => {
                self.conditional(*group, yes, no.as_deref(), states, history_observable)
            }
            Op::Assert {
                behind,
                negated,
                body,
            } => self.assertion(*behind, *negated, body, states),
            Op::At(_) => Ok(states),
            Op::Failure => Ok(Vec::new()),
        }
    }

    fn conditional(
        &mut self,
        group: u32,
        yes: &[Op],
        no: Option<&[Op]>,
        states: Vec<RepeatPrefixState>,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let mut result = Vec::new();
        for state in states {
            let taken = if state.captures.iter().any(|(g, _)| *g == group) {
                yes
            } else {
                no.unwrap_or(&[])
            };
            let walked = self.walk(taken, vec![state], history_observable)?;
            result.extend(walked);
        }
        Ok(result)
    }

    /// Reference `_PrefixWalk.walk`.
    pub fn walk(
        &mut self,
        items: &[Op],
        states: Vec<RepeatPrefixState>,
        history_observable: bool,
    ) -> Result<Vec<RepeatPrefixState>, BuilderTimeout> {
        let history = suffix_history(items, history_observable);
        let mut states = states;
        for (index, op) in items.iter().enumerate() {
            check_deadline(self.deadline)?;
            states = unique_states(self.node(op, states, history[index])?)?;
            if states.is_empty() {
                self.check_remaining_repeats(&items[index + 1..])?;
                break;
            }
        }
        Ok(states)
    }
}

/// Reference `_repeat_reaching_prefixes`.
pub fn repeat_reaching_prefixes(
    pattern: &str,
    flags: Flags,
    deadline: Option<Instant>,
    require_reachable: bool,
) -> Result<Vec<String>, BuilderTimeout> {
    let Ok((ops, final_flags)) = ast::parse(pattern, flags) else {
        return Ok(Vec::new());
    };
    let mut prefixes: Vec<String> = Vec::new();
    let alphabet = repeat_alphabet_fills(pattern, flags, deadline, true)?;
    let mut walker = PrefixWalk {
        flags: final_flags,
        prefixes: &mut prefixes,
        deadline,
        collect: true,
        alphabet,
        repeat_collector: None,
        canonical_optionals: true,
        require_reachable,
    };
    walker.walk(&ops, vec![RepeatPrefixState::default()], false)?;
    let mut unique: Vec<String> = Vec::new();
    for prefix in prefixes {
        if !prefix.is_empty() && !unique.contains(&prefix) {
            unique.push(prefix);
        }
    }
    Ok(unique)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(
        pattern: &str,
        collect: bool,
        require_reachable: bool,
    ) -> Result<(Vec<String>, Vec<RepeatPrefixState>), BuilderTimeout> {
        let (ops, flags) = crate::redos::ast::parse(pattern, Flags::default())
            .map_err(|_| BuilderTimeout("parse error".into()))?;
        let mut prefixes = Vec::new();
        let mut walker = PrefixWalk {
            flags,
            prefixes: &mut prefixes,
            deadline: None,
            collect,
            alphabet: vec!["x".to_owned(), "y".to_owned()],
            repeat_collector: None,
            canonical_optionals: true,
            require_reachable,
        };
        let states = walker.walk(&ops, vec![RepeatPrefixState::default()], false)?;
        Ok((prefixes, states))
    }

    #[test]
    fn literals_consume_their_first_member() {
        let (_prefixes, states) = walk("ab", false, false).expect("walk");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].text, "ab");
    }

    #[test]
    fn classes_consume_the_interval_start() {
        let (_prefixes, states) = walk(r"\d", false, false).expect("walk");
        assert_eq!(states[0].text, "0");
    }

    #[test]
    fn optional_atoms_branch_the_states() {
        // Canonical optional collapse: `a?` followed by `b` has the same
        // prefix language as `b`, so the states merge.
        let (_prefixes, states) = walk("a?b", false, false).expect("walk");
        let texts: Vec<String> = states.iter().map(|s| s.text.clone()).collect();
        assert_eq!(texts, vec!["b".to_owned()]);
    }

    #[test]
    fn unbounded_repeats_record_prefixes_when_collecting() {
        // Prefixes record the states before the repeat site.
        let (prefixes, _states) = walk(r"xa*", true, false).expect("walk");
        assert!(prefixes.contains(&"x".to_owned()));
        let (prefixes, _states) = walk(r"a", false, false).expect("walk");
        assert!(prefixes.is_empty());
    }

    #[test]
    fn mandatory_repeats_unroll_into_the_text() {
        let (_prefixes, states) = walk("a{2}", false, false).expect("walk");
        assert_eq!(states[0].text, "aa");
    }

    #[test]
    fn failure_nodes_kill_the_walk() {
        let (_prefixes, states) = walk(r"(?!)x", false, false).expect("walk");
        assert!(states.is_empty());
    }

    #[test]
    fn branches_union_the_alternative_states() {
        let (_prefixes, states) = walk("x|y", false, false).expect("walk");
        let texts: Vec<String> = states.iter().map(|s| s.text.clone()).collect();
        assert!(texts.contains(&"x".to_owned()));
        assert!(texts.contains(&"y".to_owned()));
    }

    #[test]
    fn negative_lookahead_excludes_the_member() {
        let (_prefixes, states) = walk(r"(?!x)\S", false, false).expect("walk");
        // The single-char forbidden word drops 'x' from the available set.
        for state in &states {
            assert_ne!(state.text, "x");
        }
    }

    #[test]
    fn positive_lookahead_pends_the_witness() {
        let (_prefixes, states) = walk(r"(?=xy)\S", false, false).expect("walk");
        // The witness pends, the anchor consumes its first char.
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].text, "x");
        assert_eq!(states[0].pending, "y");
    }

    #[test]
    fn capturing_groups_record_captures() {
        let (_prefixes, states) = walk("(x)", false, false).expect("walk");
        assert_eq!(states[0].text, "x");
        assert_eq!(states[0].captures, vec![(1, "x".to_owned())]);
    }

    #[test]
    fn backreferences_consume_the_captured_text() {
        let (_prefixes, states) = walk(r"(xy)\1", false, false).expect("walk");
        assert_eq!(states[0].text, "xyxy");
    }

    #[test]
    fn conditional_groups_take_the_live_branch() {
        let (_prefixes, states) = walk("(x)(?(1)y|z)", false, false).expect("walk");
        assert_eq!(states[0].text, "xy");
    }

    #[test]
    fn require_reachable_rejects_unresolved_repeat_sites() {
        // "a*" dies before the unstarted `b*` site when the walk cannot
        // produce states.
        let error = walk(r"(?!)b*", false, true).expect_err("unresolved");
        assert_eq!(
            error.0,
            "Pattern validation cannot resolve repeat-site prefixes"
        );
    }

    #[test]
    fn assertion_witness_budget_is_enforced() {
        // A negative lookbehind whose prefix ends on the forbidden char
        // cannot be resolved once captures are in play.
        let error = walk(r"(x)(?<!x)a", false, false).expect_err("capture lookbehind");
        assert_eq!(
            error.0,
            "Pattern validation cannot resolve capture-dependent lookbehind"
        );
    }

    #[test]
    fn unique_states_budget_is_enforced() {
        // The state limit and text budget guards live in unique_states.
        let many: Vec<RepeatPrefixState> = (0..=PREFIX_WALK_STATE_LIMIT)
            .map(|index| RepeatPrefixState {
                text: format!("s{index}"),
                ..RepeatPrefixState::default()
            })
            .collect();
        let error = unique_states(many).expect_err("state budget exceeded");
        assert_eq!(
            error.0,
            "Pattern validation repeat-prefix state budget exceeded"
        );
        let long: Vec<RepeatPrefixState> = vec![RepeatPrefixState {
            text: "a".repeat(PREFIX_WALK_TEXT_BUDGET + 1),
            ..RepeatPrefixState::default()
        }];
        let error = unique_states(long).expect_err("text budget exceeded");
        assert_eq!(
            error.0,
            "Pattern validation repeat-prefix text budget exceeded"
        );
    }

    #[test]
    fn repeat_reaching_prefixes_returns_deduped_prefixes() {
        // Prefixes are the states recorded before each repeated site.
        let prefixes =
            repeat_reaching_prefixes("xa*b", Flags::default(), None, false).expect("prefixes");
        assert!(prefixes.contains(&"x".to_owned()));
        assert!(prefixes.iter().all(|prefix| !prefix.is_empty()));
        let mut sorted = prefixes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(prefixes.len(), sorted.len(), "deduped");
    }

    #[test]
    fn repeat_reaching_prefixes_parse_failures_are_empty() {
        let prefixes =
            repeat_reaching_prefixes("[oops", Flags::default(), None, false).expect("empty");
        assert!(prefixes.is_empty());
    }

    #[test]
    fn check_deadline_maps_all_three_states() {
        assert!(check_deadline(None).is_ok());
        assert!(check_deadline(Some(Instant::now() + std::time::Duration::from_secs(60))).is_ok());
        let error = check_deadline(Some(Instant::now() - std::time::Duration::from_secs(1)))
            .expect_err("expired");
        assert_eq!(
            error.0,
            "Pattern validation repeat-prefix construction exceeded its deadline"
        );
    }

    #[test]
    fn assertion_witnesses_reject_unresolved_nested_assertions() {
        let (ops, _) = crate::redos::ast::parse("a(?=x)", Flags::default())
            .map_err(|_| BuilderTimeout("parse error".into()))
            .expect("parses");
        let error = assertion_witnesses(&ops, Flags::default(), None).expect_err("pending");
        assert_eq!(
            error.0,
            "Pattern validation cannot resolve nested assertion constraints"
        );
    }

    #[test]
    fn collected_prefixes_honor_the_candidate_budget() {
        // Seed the collector past its budget; the very next collected
        // repeat must trip the guard.
        let (ops, flags) = crate::redos::ast::parse("x+", Flags::default())
            .map_err(|_| BuilderTimeout("parse error".into()))
            .expect("parses");
        let mut prefixes = vec![String::new(); REPEAT_PREFIX_STATE_LIMIT * 4 + 1];
        let mut walker = PrefixWalk {
            flags,
            prefixes: &mut prefixes,
            deadline: None,
            collect: true,
            alphabet: Vec::new(),
            repeat_collector: None,
            canonical_optionals: true,
            require_reachable: false,
        };
        let error = walker
            .walk(&ops, vec![RepeatPrefixState::default()], false)
            .expect_err("budget");
        assert_eq!(
            error.0,
            "Pattern validation repeat-prefix candidate budget exceeded"
        );
    }

    #[test]
    fn a_fixed_repeat_of_a_state_unchanging_body_stops_early() {
        // Anchors leave the walk state untouched, so the fixed-repeat loop
        // breaks out instead of spinning to its bound.
        let (_prefixes, states) = walk(r"(?:\b){2}x", false, false).expect("walk");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].text, "x");
    }

    #[test]
    fn pending_assertion_states_are_replayed_after_a_repeat() {
        // The lookahead defers pending states that the repeat loop must
        // replay to keep the prefix language complete.
        let (_prefixes, states) = walk(r"(?:x(?=y))+", true, false).expect("walk");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].text, "x");
    }

    #[test]
    fn a_conditional_without_else_walks_an_empty_branch() {
        // The group was never captured, so the conditional takes the
        // missing else branch, which contributes nothing.
        let (_prefixes, states) = walk(r"(?(1)b)x", false, false).expect("walk");
        let texts: Vec<String> = states.iter().map(|s| s.text.clone()).collect();
        assert_eq!(texts, vec!["x".to_owned()]);
    }

    #[test]
    fn pending_replay_stops_at_a_fixed_point() {
        // The lookahead's witness merges back into the pending state, so
        // the replay loop detects no progress and stops.
        let (_prefixes, states) = walk(r"(?:(?=x))+", true, false).expect("walk");
        assert_eq!(states.len(), 1);
    }
}
