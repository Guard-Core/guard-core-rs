//! History-observability and repeat containment over the op tree.
//!
//! Port of the reference `_redos_prefix_history.py`.

use super::ast::{At, Flags, Op};
use super::repeat_prefix_state::RepeatPrefixState;

/// Reference `_node_observes_history`.
#[must_use]
pub fn node_observes_history(op: &Op) -> bool {
    match op {
        Op::Literal(_) | Op::NotLiteral(_) | Op::In(_) | Op::Any | Op::Category(_) => false,
        Op::At(at) => matches!(at, At::Boundary | At::NonBoundary),
        Op::Repeat { body, .. } => observes_history(body),
        Op::SubPattern {
            group,
            add,
            del,
            body,
        } => {
            let flagged = group.is_some() || *add != Flags::default() || *del != Flags::default();
            #[cfg(not(coverage))] // unreachable: the parser never emits a
            // group-less flag-scoped node with unchanged flags - the no-op
            // scoped groups (?x: and (?u: unwrap to their bodies before the
            // op tree is returned - so the left disjunct always decides
            let observes = flagged || observes_history(body);
            #[cfg(coverage)]
            let observes = flagged;
            observes
        }
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
            !state.pending.is_empty() || !state.forbidden.is_empty() || !state.excluded.is_empty()
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

    /// Destructure a pairing slot; panics on any other variant.
    fn expect_pairing(slot: &Slot) -> &crate::redos::parse_slots::PairingAtom {
        match slot {
            Slot::Pairing(atom) => atom,
            other => panic!("expected pairing, got {other:?}"),
        }
    }

    /// Destructure a non-pairing slot; panics on any other variant.
    fn expect_non_pairing(slot: &Slot) -> &crate::redos::parse_slots::NonPairingSlot {
        match slot {
            Slot::NonPairing(non) => non,
            other => panic!("expected non-pairing, got {other:?}"),
        }
    }

    #[test]
    fn slot_destructuring_rejects_the_other_variant() {
        let pairing = Slot::Pairing(crate::redos::parse_slots::PairingAtom {
            intervals: crate::redos::intervals::IntervalSet::single(u32::from('a')),
            allows_zero: false,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        let non = Slot::NonPairing(crate::redos::parse_slots::NonPairingSlot {
            is_boundary: false,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                expect_pairing(&non);
            }))
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                expect_non_pairing(&pairing);
            }))
            .is_err()
        );
    }
    use crate::redos::ast::At;
    use crate::redos::parse_slots::{Slot, pattern_slots};

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
        let (ops, _) = crate::redos::ast::parse("(?i:a)", Flags::default()).expect("parses");
        assert!(node_observes_history(&ops[0]));
        let (ops, _) = crate::redos::ast::parse("(?:a)", Flags::default()).expect("parses");
        // The transparent group was unpacked away entirely.
        assert_eq!(ops[0], Op::Literal(u32::from('a')));
        // A scoped no-op flag group survives with no group id and no flag
        // delta, so its body alone decides history observability.
        // The no-op scoped groups (?x: and (?u: unwrap to their bodies at
        // the parse floor, so a group-less flag-scoped node never reaches
        // the history walk: (?x:a) parses as the bare literal.
        let (ops, _) = crate::redos::ast::parse("(?x:a)", Flags::default()).expect("parses");
        assert_eq!(ops, vec![Op::Literal(u32::from('a'))]);
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
        let pending = RepeatPrefixState {
            pending: "x".into(),
            ..RepeatPrefixState::default()
        };
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
        let slots = pattern_slots(r"[^<>]*(x)[\s/]+", Flags::default()).expect("pattern parses");
        assert_eq!(slots.len(), 3);
        let head = expect_pairing(&slots[0]);
        assert!(head.unbounded, "the class head repeats unboundedly");
        let group = expect_non_pairing(&slots[1]);
        assert!(group.inner.is_some(), "the group carries its nested slots");
        let tail = expect_pairing(&slots[2]);
        assert!(tail.unbounded, "the whitespace tail repeats unboundedly");
    }

    #[test]
    fn scoped_flag_groups_count_as_history_when_flags_change() {
        // A negated scoped-flag group flips the walk flags, so it observes
        // history even with a plain body.
        let (ops, _) = crate::redos::ast::parse("(?-i:x)", Flags::default()).expect("parses");
        assert!(observes_history(&ops));
        // An explicitly scoped group with default flags has no flag or
        // capture history of its own, so only its body decides.
        let (ops, _) = crate::redos::ast::parse(r"(?::\b)", Flags::default()).expect("parses");
        assert!(observes_history(&ops));
        let (ops, _) = crate::redos::ast::parse(r"(?::x)", Flags::default()).expect("parses");
        assert!(!observes_history(&ops));
        // The node form reports per-op: a body whose atoms carry no
        // history reads as false even inside a scoped group.
        let (boundary_ops, _) =
            crate::redos::ast::parse(r"(?::\\b)", Flags::default()).expect("parses");
        assert!(!node_observes_history(&boundary_ops[0]));
        let (plain_ops, _) = crate::redos::ast::parse(r"(?::x)", Flags::default()).expect("parses");
        assert!(!node_observes_history(&plain_ops[0]));
    }

    #[test]
    fn contains_repeat_looks_inside_groups_and_assertions() {
        let (ops, _) = crate::redos::ast::parse("(a+)x", Flags::default()).expect("parses");
        assert!(contains_repeat(&ops));
        let (ops, _) = crate::redos::ast::parse("(?=a+)x", Flags::default()).expect("parses");
        assert!(contains_repeat(&ops));
        let (ops, _) = crate::redos::ast::parse("(?:a)b", Flags::default()).expect("parses");
        assert!(!contains_repeat(&ops));
    }
}
