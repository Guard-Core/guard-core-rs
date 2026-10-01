//! Exact-state narrowing for group crossings.
//!
//! Port of the reference `_redos_exact_state.py`.

use super::intervals::IntervalSet;
use super::parse_slots::{PairingAtom, Slot};

/// Reference `_MAX_GROUP_CROSSING_DEPTH`.
pub const MAX_GROUP_CROSSING_DEPTH: usize = 16;

pub(super) fn narrow_exact_state_raw(
    state: Option<&IntervalSet>,
    right: Option<&IntervalSet>,
) -> Option<IntervalSet> {
    Some(state?.intersection(right?))
}

pub(super) fn exact_overlap_fill_raw(
    state: Option<&IntervalSet>,
    right: Option<&IntervalSet>,
) -> Option<char> {
    let member = state?.intersection(right?).first_member()?;
    char::from_u32(member)
}

fn isolated_alternative_exact_state(
    alt_slots: &[Slot],
    depth: usize,
) -> Option<IntervalSet> {
    let mut state: Option<IntervalSet> = Some(IntervalSet::full());
    for slot in alt_slots {
        match slot {
            Slot::Pairing(PairingAtom {
                intervals,
                allows_zero: false,
                ..
            }) => {
                state = narrow_exact_state_raw(state.as_ref(), Some(intervals));
            }
            Slot::Pairing(_) => {}
            Slot::NonPairing(non_pairing) => {
                if non_pairing.is_boundary {
                    let group_state = match &non_pairing.inner {
                        Some(inner) => isolated_group_exact_state(inner, depth + 1),
                        None => return None,
                    };
                    state = narrow_exact_state_raw(state.as_ref(), group_state.as_ref());
                }
            }
        }
        if state.is_none() {
            return None;
        }
    }
    state
}

/// Reference `_isolated_group_exact_state`.
#[must_use]
pub fn isolated_group_exact_state(
    alternatives: &[Vec<Slot>],
    depth: usize,
) -> Option<IntervalSet> {
    if depth > MAX_GROUP_CROSSING_DEPTH {
        return None;
    }
    let mut combined: Option<IntervalSet> = None;
    for alt in alternatives {
        let Some(alt_state) = isolated_alternative_exact_state(alt, depth) else {
            continue;
        };
        combined = Some(match combined {
            None => alt_state,
            Some(existing) => existing.union(&alt_state),
        });
    }
    combined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redos::ast::Flags;
    use exact_overlap_fill_raw as exact_overlap_fill;
    use narrow_exact_state_raw as narrow_exact_state;
    use crate::redos::parse_slots::{pattern_slots, NonPairingSlot};

    fn slots(pattern: &str) -> Vec<Slot> {
        pattern_slots(pattern, Flags::default()).expect("pattern parses")
    }

    #[test]
    fn narrow_returns_none_when_either_state_is_missing() {
        assert_eq!(narrow_exact_state(None, Some(&IntervalSet::full())), None);
        assert_eq!(narrow_exact_state(Some(&IntervalSet::full()), None), None);
    }

    #[test]
    fn narrow_intersects_two_states() {
        let narrowed = narrow_exact_state(
            Some(&IntervalSet::from_range(0, 10)),
            Some(&IntervalSet::from_range(5, 15)),
        );
        assert_eq!(narrowed, Some(IntervalSet::from_range(5, 10)));
    }

    #[test]
    fn exact_fill_returns_none_when_either_state_is_missing() {
        assert_eq!(exact_overlap_fill(None, Some(&IntervalSet::full())), None);
        assert_eq!(exact_overlap_fill(Some(&IntervalSet::full()), None), None);
    }

    #[test]
    fn exact_fill_returns_none_without_an_overlap() {
        assert_eq!(
            exact_overlap_fill(
                Some(&IntervalSet::single(u32::from('a'))),
                Some(&IntervalSet::single(u32::from('b')))
            ),
            None
        );
    }

    #[test]
    fn exact_fill_finds_the_overlap() {
        assert_eq!(
            exact_overlap_fill(
                Some(&IntervalSet::single(u32::from('z'))),
                Some(&IntervalSet::single(u32::from('z')))
            ),
            Some('z')
        );
    }

    #[test]
    fn isolated_alternative_skips_a_zero_admitting_atom() {
        let pattern_slots_vec = slots("a*");
        let Slot::Pairing(atom) = &pattern_slots_vec[0] else {
            panic!("expected pairing atom");
        };
        let zero_atom = PairingAtom {
            allows_zero: true,
            ..atom.clone()
        };
        let state = isolated_alternative_exact_state(
            &[Slot::Pairing(zero_atom)],
            0,
        );
        assert_eq!(state, Some(IntervalSet::full()));
    }

    #[test]
    fn isolated_alternative_narrows_through_a_mandatory_atom() {
        let pattern_slots_vec = slots("z");
        let state = isolated_alternative_exact_state(&[pattern_slots_vec[0].clone()], 0);
        let Some(state) = state else {
            panic!("expected a state");
        };
        assert!(state.contains(u32::from('z')));
        assert!(!state.contains(u32::from('y')));
    }

    #[test]
    fn isolated_alternative_returns_none_for_a_hard_boundary() {
        let hard = Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        assert_eq!(isolated_alternative_exact_state(&[hard], 0), None);
    }

    #[test]
    fn isolated_alternative_passes_through_a_transparent_slot() {
        let transparent = Slot::NonPairing(NonPairingSlot {
            is_boundary: false,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        assert_eq!(
            isolated_alternative_exact_state(&[transparent], 0),
            Some(IntervalSet::full())
        );
    }

    #[test]
    fn isolated_alternative_recurses_into_a_nested_group() {
        let pattern_slots_vec = slots("(z)");
        let state = isolated_alternative_exact_state(&[pattern_slots_vec[0].clone()], 0);
        let Some(state) = state else {
            panic!("expected a state");
        };
        assert!(state.contains(u32::from('z')));
        assert!(!state.contains(u32::from('y')));
    }

    #[test]
    fn isolated_alternative_returns_none_for_a_none_group_state() {
        let hard = Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        let inner_group = Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: Some(vec![vec![hard]]),
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        assert_eq!(isolated_alternative_exact_state(&[inner_group], 0), None);
    }

    #[test]
    fn isolated_group_rejects_past_the_max_depth() {
        let pattern_slots_vec = slots("z");
        assert_eq!(
            isolated_group_exact_state(&[pattern_slots_vec.clone()], 999),
            None
        );
    }

    #[test]
    fn isolated_group_skips_alternatives_that_cannot_narrow() {
        let pattern_slots_vec = slots("z");
        let hard = Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        let state = isolated_group_exact_state(
            &[vec![hard], pattern_slots_vec.clone()],
            0,
        );
        assert_eq!(state, Some(IntervalSet::single(u32::from('z'))));
    }

    #[test]
    fn isolated_group_unions_two_alternatives() {
        let a = slots("a");
        let b = slots("b");
        let state = isolated_group_exact_state(&[a.clone(), b.clone()], 0);
        let expected = match (a[0].clone(), b[0].clone()) {
            (Slot::Pairing(left), Slot::Pairing(right)) => {
                left.intervals.union(&right.intervals)
            }
            _ => panic!("expected pairing atoms"),
        };
        assert_eq!(state, Some(expected));
    }

    #[test]
    fn isolated_group_returns_none_when_every_alternative_fails() {
        let hard = Slot::NonPairing(NonPairingSlot {
            is_boundary: true,
            inner: None,
            unbounded: false,
            max_repeat: None,
            variable_bounded: false,
        });
        assert_eq!(isolated_group_exact_state(&[vec![hard.clone()], vec![hard]], 0), None);
    }
}
