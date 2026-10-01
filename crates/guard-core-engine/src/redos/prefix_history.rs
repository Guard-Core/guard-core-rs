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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::At;
    use crate::redos::parse_slots::{pattern_slots, Slot};

    fn parse(pattern: &str) -> Vec<Op> {
        crate::redos::ast::parse(pattern, Flags::default())
            .expect("pattern parses")
            .0
    }

    #[test]
    fn pairing_ops_never_observe_history() {
        assert!(!node_observes_history(&Op::Literal(u32::from('a'))));
        assert!(!node_observes_history(&Op::NotLiteral(u32::from('a'))));
        assert!(!node_observes_history(&Op::Any));
        assert!(!node_observes_history(&Op::In(vec![])));
        assert!(!node_observes_history(&Op::Category(
            crate::redos::ast::Category::Digit
        )));
    }

    #[test]
    fn boundary_anchors_observe_history_but_line_anchors_do_not() {
        assert!(node_observes_history(&Op::At(At::Boundary)));
        assert!(node_observes_history(&Op::At(At::NonBoundary)));
        assert!(!node_observes_history(&Op::At(At::Beginning)));
        assert!(!node_observes_history(&Op::At(At::End)));
    }

    #[test]
    fn repeats_observe_history_through_their_body() {
        let repeat = Op::Repeat {
            kind: crate::redos::ast::RepeatKind::Greedy,
            low: 0,
            high: None,
            body: vec![Op::At(At::Boundary)],
        };
        assert!(node_observes_history(&repeat));
        let plain = Op::Repeat {
            kind: crate::redos::ast::RepeatKind::Greedy,
            low: 0,
            high: None,
            body: vec![Op::Literal(u32::from('a'))],
        };
        assert!(!node_observes_history(&plain));
    }

    #[test]
    fn capturing_or_reflagged_groups_observe_history() {
        let (ops, _) = crate::redos::ast::parse("(a)", Flags::default()).expect("parses");
        assert!(node_observes_history(&ops[0]));
        let (ops, _) =
            crate::redos::ast::parse("(?i:a)", Flags::default()).expect("parses");
        assert!(node_observes_history(&ops[0]));
        let (ops, _) =
            crate::redos::ast::parse("(?:a)", Flags::default()).expect("parses");
        // The transparent group was unpacked away entirely.
        assert!(matches!(ops[0], Op::Literal(_)));
    }

    #[test]
    fn branches_observe_history_when_any_alternative_does() {
        let (ops, _) = crate::redos::ast::parse("(a)|b", Flags::default()).expect("parses");
        assert!(node_observes_history(&ops[0]));
    }

    #[test]
    fn everything_else_observes_history_conservatively() {
        assert!(node_observes_history(&Op::GroupRef(1)));
        assert!(node_observes_history(&Op::Failure));
        assert!(node_observes_history(&Op::GroupRefExists {
            group: 1,
            yes: vec![],
            no: None,
        }));
        assert!(node_observes_history(&Op::Assert {
            behind: false,
            negated: false,
            body: vec![],
        }));
    }

    #[test]
    fn suffix_history_marks_what_comes_after_each_node() {
        let items = parse("a\\bx");
        let history = suffix_history(&items, false);
        assert_eq!(history, vec![true, false, false]);
    }

    #[test]
    fn suffix_history_enclosing_flag_marks_everything() {
        let items = parse("ab");
        assert_eq!(suffix_history(&items, true), vec![true, true]);
    }

    #[test]
    fn optional_states_equivalent_requires_clean_states() {
        let body = parse("a");
        let states = vec![RepeatPrefixState::default()];
        assert!(optional_states_are_equivalent(&body, &states, false));
        assert!(!optional_states_are_equivalent(&body, &states, true));
        let mut pending = RepeatPrefixState::default();
        pending.pending = "x".into();
        assert!(!optional_states_are_equivalent(&body, &[pending], false));
    }

    #[test]
    fn optional_states_equivalent_rejects_a_history_observing_body() {
        let body = parse("\\bx");
        assert!(!optional_states_are_equivalent(
            &body,
            &[RepeatPrefixState::default()],
            false
        ));
    }

    #[test]
    fn contains_repeat_finds_nested_repeats() {
        assert!(contains_repeat(&parse("(?:a*)+")));
        assert!(contains_repeat(&parse("a{2,3}")));
        // Any repeat whose high exceeds 1 counts, fixed bounds included.
        assert!(contains_repeat(&parse("a{2}")));
        assert!(!contains_repeat(&parse("a{1}")));
        assert!(!contains_repeat(&parse("abc")));
        assert!(contains_repeat(&parse("(?:(a)*)")));
        assert!(contains_repeat(&parse("(?:a*|b)")));
    }

    #[test]
    fn contains_repeat_unbounded_reads_as_greater_than_one() {
        assert!(contains_repeat(&parse("a*")));
        assert!(contains_repeat(&parse("a+")));
        assert!(!contains_repeat(&parse("a?")));
    }

    #[test]
    fn slots_walk_separates_pairing_and_non_pairing() {
        let slots = pattern_slots(r"[^<>]*(x)[\s/]+", Flags::default())
            .expect("pattern parses");
        assert_eq!(slots.len(), 3);
        assert!(matches!(slots[0], Slot::Pairing(_)));
        assert!(matches!(slots[1], Slot::NonPairing(_)));
        assert!(matches!(slots[2], Slot::Pairing(_)));
    }
}
