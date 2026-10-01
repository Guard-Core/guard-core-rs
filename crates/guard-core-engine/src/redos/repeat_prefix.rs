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
use super::prefix_history::{
    contains_repeat, optional_states_are_equivalent, suffix_history,
};
use super::repeat_alphabet::repeat_alphabet_fills;
use super::repeat_lookbehind::walk_negative_behind;
use super::repeat_prefix_state::{
    capture_state, consume_atom, consume_piece, positive_assertion, state_text_size,
    RepeatPrefixState, REPEAT_PREFIX_STATE_LIMIT, PREFIX_WALK_STATE_LIMIT,
    PREFIX_WALK_TEXT_BUDGET,
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
    if states
        .iter()
        .any(|state| {
            !state.pending.is_empty()
                || !state.forbidden.is_empty()
                || !state.excluded.is_empty()
        })
    {
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
            return self.pending_repeats(
                body,
                combined,
                expanded,
                remaining,
                history_observable,
            );
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
            return walk_negative_behind(
                body,
                self.flags,
                &witnesses,
                &states,
                &self.alphabet,
            );
        }
        let mut result = Vec::new();
        for state in &states {
            result.extend(super::repeat_prefix_state::negative_assertion(
                body,
                self.flags,
                &witnesses,
                state,
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
            Op::Literal(_)
            | Op::NotLiteral(_)
            | Op::In(_)
            | Op::Any
            | Op::Category(_) => self.atoms(op, states),
            Op::Repeat {
                kind: _,
                low,
                high,
                body,
            } => self.repeat(*low, *high, body, states, history_observable),
            Op::GroupRef(group) => self.backreference(*group, states),
            Op::Branch(alternatives) => {
                self.branch(alternatives, states, history_observable)
            }
            Op::SubPattern {
                group,
                add,
                del,
                body,
            } => self.group(*group, *add, *del, body, states, history_observable),
            Op::GroupRefExists { group, yes, no } => {
                self.conditional(*group, yes, no.as_deref(), states, history_observable)
            }
            Op::Assert { behind, body } => {
                self.assertion(*behind, false, body, states)
            }
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
