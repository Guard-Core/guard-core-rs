//! History-observability and repeat containment over the op tree.
//!
//! Port of the reference `_redos_prefix_history.py`.

use super::ast::{At, Flags, Op};
use super::repeat_prefix_state::RepeatPrefixState;

/// Reference `_node_observes_history`.
#[must_use]
pub fn node_observes_history(op: &Op) -> bool {
    match op {
        Op::Literal(_)
        | Op::NotLiteral(_)
        | Op::In(_)
        | Op::Any
        | Op::Category(_) => false,
        Op::At(at) => matches!(at, At::Boundary | At::NonBoundary),
        Op::Repeat { body, .. } => observes_history(body),
        Op::SubPattern {
            group,
            add,
            del,
            body,
        } => group.is_some() || *add != Flags::default() || *del != Flags::default()
            || observes_history(body),
        Op::Branch(alternatives) => alternatives.iter().any(|alt| observes_history(alt)),
        _ => true,
    }
}

/// Reference `_observes_history`.
#[must_use]
pub fn observes_history(items: &[Op]) -> bool {
    items.iter().any(node_observes_history)
}

/// Reference `_suffix_history`: for every node, whether the nodes after it
/// observe history.
#[must_use]
pub fn suffix_history(items: &[Op], enclosing: bool) -> Vec<bool> {
    let mut observed = enclosing;
    let mut result = Vec::with_capacity(items.len());
    for op in items.iter().rev() {
        result.push(observed);
        observed = observed || node_observes_history(op);
    }
    result.reverse();
    result
}

/// Reference `_optional_states_are_equivalent`.
#[must_use]
pub fn optional_states_are_equivalent(
    body: &[Op],
    states: &[RepeatPrefixState],
    history_observable: bool,
) -> bool {
    !history_observable
        && !observes_history(body)
        && !states.iter().any(|state| {
            !state.pending.is_empty()
                || !state.forbidden.is_empty()
                || !state.excluded.is_empty()
        })
}

/// Reference `_contains_repeat`.
#[must_use]
pub fn contains_repeat(items: &[Op]) -> bool {
    items.iter().any(node_contains_repeat)
}

fn node_contains_repeat(op: &Op) -> bool {
    match op {
        // Unbounded (`None`) repeats read as `> 1` like the reference's
        // MAXREPEAT sentinel.
        Op::Repeat { high, body, .. } => {
            high.is_none() || high.is_some_and(|high| high > 1) || contains_repeat(body)
        }
        Op::SubPattern { body, .. } => contains_repeat(body),
        Op::Branch(alternatives) => alternatives.iter().any(|alt| contains_repeat(alt)),
        Op::Assert { body, .. } => contains_repeat(body),
        _ => false,
    }
}
